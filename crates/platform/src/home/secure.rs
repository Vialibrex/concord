use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, fchown};
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

impl Owner {
    /// Elevated means root acting for a user: the real uid is not root's.
    pub fn detect() -> Option<Owner> {
        // SAFETY: these calls take no arguments and cannot fail.
        let (euid, uid, gid) = unsafe { (libc::geteuid(), libc::getuid(), libc::getgid()) };
        (euid == 0 && uid != 0).then_some(Owner { uid, gid })
    }
}

fn name_of(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn openat(dir: BorrowedFd<'_>, name: &OsStr, flags: libc::c_int, mode: u32) -> io::Result<OwnedFd> {
    let name = name_of(name)?;
    // SAFETY: `dir` is open, `name` is NUL-terminated, and a returned descriptor is owned here.
    unsafe {
        let fd = libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode as libc::c_uint,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

fn cvt(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mkdirat(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    let name = name_of(name)?;
    // SAFETY: `dir` is open and `name` is NUL-terminated.
    cvt(unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) })
}

fn unlinkat(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    let name = name_of(name)?;
    // SAFETY: `dir` is open and `name` is NUL-terminated.
    cvt(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })
}

fn renameat(dir: BorrowedFd<'_>, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (from, to) = (name_of(from)?, name_of(to)?);
    let fd = dir.as_raw_fd();
    // SAFETY: `dir` is open and both names are NUL-terminated.
    cvt(unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) })
}

/// Opens each component relative to its parent without following a symlink, so
/// swapping a directory for a link after the path was checked cannot redirect it.
pub fn open_dir(base: &Path, names: &[OsString], create: Option<Owner>) -> io::Result<OwnedFd> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(base)?;
    let mut dir = OwnedFd::from(root);
    for name in names {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        dir = match openat(dir.as_fd(), name, flags, 0) {
            Ok(next) => next,
            Err(err) if err.kind() == io::ErrorKind::NotFound && create.is_some() => {
                let made = match mkdirat(dir.as_fd(), name) {
                    Ok(()) => true,
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => false,
                    Err(err) => return Err(err),
                };
                let next = openat(dir.as_fd(), name, flags, 0)?;
                if let (true, Some(owner)) = (made, create) {
                    fchown(&next, Some(owner.uid), Some(owner.gid))?;
                }
                next
            }
            Err(err) => return Err(err),
        };
    }
    Ok(dir)
}

fn split_name(names: &[OsString]) -> io::Result<(&[OsString], &OsString)> {
    match names.split_last() {
        Some((name, parents)) => Ok((parents, name)),
        None => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

pub fn write_file(
    base: &Path,
    names: &[OsString],
    temp: &OsStr,
    owner: Owner,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<()> {
    let (parents, name) = split_name(names)?;
    let dir = open_dir(base, parents, Some(owner))?;
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW;
    let mut file = File::from(openat(dir.as_fd(), temp, flags, 0o644)?);
    let written = (|| {
        fchown(&file, Some(owner.uid), Some(owner.gid))?;
        fill(&mut file)?;
        file.sync_all()?;
        renameat(dir.as_fd(), temp, name)
    })();
    if written.is_err() {
        let _ = unlinkat(dir.as_fd(), temp);
    }
    written
}

pub fn read_file(base: &Path, names: &[OsString]) -> io::Result<Vec<u8>> {
    let (parents, name) = split_name(names)?;
    let dir = open_dir(base, parents, None)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let mut file = File::from(openat(dir.as_fd(), name, flags, 0)?);
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub fn remove_file(base: &Path, names: &[OsString]) -> io::Result<()> {
    let (parents, name) = split_name(names)?;
    let dir = open_dir(base, parents, None)?;
    unlinkat(dir.as_fd(), name)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, symlink};

    use super::*;
    use crate::HomeDir;

    fn current() -> Owner {
        // SAFETY: these calls take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Owner { uid, gid }
    }

    fn names(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn created_files_and_directories_belong_to_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let owner = current();
        let home = HomeDir::with_owner(dir.path(), owner.uid, owner.gid);
        assert!(home.is_elevated());

        home.write_atomic("profiles/7/config.yaml", b"mixed-port: 7890\n")
            .unwrap();
        home.create_dir_all("providers/a").unwrap();

        for path in [
            "profiles",
            "profiles/7",
            "profiles/7/config.yaml",
            "providers/a",
        ] {
            let meta = std::fs::metadata(dir.path().join(path)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (owner.uid, owner.gid), "{path}");
        }
        assert_eq!(
            home.read("profiles/7/config.yaml").unwrap(),
            b"mixed-port: 7890\n"
        );
        home.write_atomic("profiles/7/config.yaml", b"replaced")
            .unwrap();
        assert_eq!(home.read("profiles/7/config.yaml").unwrap(), b"replaced");
        home.remove_file("profiles/7/config.yaml").unwrap();
        assert_eq!(
            std::fs::read_dir(dir.path().join("profiles/7"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn a_directory_swapped_for_a_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), dir.path().join("profiles")).unwrap();

        let temp = OsString::from(".t.tmp");
        let written = write_file(
            dir.path(),
            &names(&["profiles", "x"]),
            &temp,
            current(),
            |_| Ok(()),
        );
        assert!(written.is_err());
        assert!(read_file(dir.path(), &names(&["profiles", "x"])).is_err());
        assert!(open_dir(dir.path(), &names(&["profiles"]), Some(current())).is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_planted_final_symlink_is_replaced_and_its_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        symlink(&victim, dir.path().join("config.yaml")).unwrap();

        let owner = current();
        let temp = OsString::from(".c.tmp");
        write_file(dir.path(), &names(&["config.yaml"]), &temp, owner, |file| {
            io::Write::write_all(file, b"new")
        })
        .unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert!(
            !std::fs::symlink_metadata(dir.path().join("config.yaml"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.yaml")).unwrap(),
            "new"
        );
    }

    #[test]
    fn reads_refuse_symlinks_and_special_files_but_allow_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secret"), "s").unwrap();
        std::fs::hard_link(dir.path().join("secret"), dir.path().join("alias")).unwrap();
        symlink(dir.path().join("secret"), dir.path().join("soft")).unwrap();
        let fifo = CString::new(dir.path().join("pipe").as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        assert_eq!(read_file(dir.path(), &names(&["alias"])).unwrap(), b"s");
        for name in ["soft", "pipe"] {
            assert!(read_file(dir.path(), &names(&[name])).is_err(), "{name}");
        }
    }
}
