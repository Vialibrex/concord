//! A packaged Concord pins the library to the SHA-256 it was built with, as FlClash's Helper pins
//! the Core it starts with privileges: a library swapped in beside the Core must not run in it.
//! The bytes are checked, then loaded from where nobody else can change them: an anonymous
//! memfd on Linux, elsewhere a directory made new for this process that only it may write.

use std::fs;
use std::io::{self, Write as _};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::LoadError;

/// `CONCORD_TSNET_SHA256` when Concord was built; unset in development and `concord run`, where
/// the library loads unchecked.
const PINNED: Option<&str> = option_env!("CONCORD_TSNET_SHA256");
#[cfg(any(not(target_os = "linux"), test))]
const STAGE_PREFIX: &str = "concord-tsnet-";

pub(crate) enum Opened {
    Loaded(libloading::Library),
    /// Nothing loadable at this path; the next candidate may have it.
    Missing(String),
}

pub(crate) fn open(path: &Path, elevated: bool) -> Result<Opened, LoadError> {
    let Some(pinned) = PINNED else {
        // SAFETY: the library is Concord's own Go build; loading runs the Go runtime's
        // initialisers, which start its threads and touch no state of this process.
        return Ok(match unsafe { libloading::Library::new(path) } {
            Ok(lib) => Opened::Loaded(lib),
            Err(err) => Opened::Missing(format!("{}: {err}", path.display())),
        });
    };
    let bytes = match read_file(path) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(Opened::Missing(format!("{}: {err}", path.display()))),
    };
    check(path, &bytes, pinned, elevated)?;
    load(&bytes)
        .map(Opened::Loaded)
        .map_err(|err| LoadError::Stage(err.to_string()))
}

fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    fs::read(path)
}

/// Elevated, it keeps the hash it found to itself: the file may be one only root may read.
fn check(path: &Path, bytes: &[u8], pinned: &'static str, elevated: bool) -> Result<(), LoadError> {
    let found: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if found.eq_ignore_ascii_case(pinned) {
        return Ok(());
    }
    Err(LoadError::Mismatch {
        path: path.display().to_string(),
        found: (!elevated).then_some(found),
        pinned,
    })
}

#[cfg(target_os = "linux")]
fn load(bytes: &[u8]) -> io::Result<libloading::Library> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: a valid NUL-terminated name and flags; the result is checked below.
    let fd = unsafe { libc::memfd_create(c"concord-tsnet".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and nothing else owns it.
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    let path = format!("/proc/self/fd/{}", file.as_raw_fd());
    // SAFETY: as in `open`; the bytes are the checked library, which nobody else can reach.
    unsafe { libloading::Library::new(path) }.map_err(io::Error::other)
}

#[cfg(not(target_os = "linux"))]
fn load(bytes: &[u8]) -> io::Result<libloading::Library> {
    let root = stage_root(concord_platform::is_setuid_elevated())?;
    let copy = stage(bytes, &root)?;
    // SAFETY: as in `open`; the copy is the checked library in a directory only this process's
    // user may write.
    let lib = unsafe { libloading::Library::new(&copy) }.map_err(io::Error::other)?;
    remove_stale(&root, copy.parent());
    Ok(lib)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stage_root(elevated: bool) -> io::Result<std::path::PathBuf> {
    if elevated {
        trusted_root(&own_temp_dir()?)
    } else {
        Ok(std::env::temp_dir())
    }
}

#[cfg(windows)]
fn stage_root(_elevated: bool) -> io::Result<std::path::PathBuf> {
    Ok(std::env::temp_dir())
}

/// Kept per user under `/var/folders`, not taken from the environment the caller set.
#[cfg(target_vendor = "apple")]
fn own_temp_dir() -> io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut buf = vec![0u8; 1024];
    // SAFETY: `buf` is writable for its whole length, which is passed with it.
    let len = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    if len > buf.len() {
        return Err(io::Error::other(
            "the temporary directory's path is too long",
        ));
    }
    buf.truncate(len - 1);
    Ok(std::ffi::OsString::from_vec(buf).into())
}

#[cfg(all(unix, not(any(target_os = "linux", target_vendor = "apple"))))]
fn own_temp_dir() -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no directory to stage the library in that only this user may change",
    ))
}

/// Refused unless root or this user owns each level, so nobody else can replace what is staged.
#[cfg(all(unix, any(not(target_os = "linux"), test)))]
fn trusted_root(dir: &Path) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let resolved = fs::canonicalize(dir)?;
    for dir in resolved.ancestors() {
        let meta = fs::metadata(dir)?;
        if (meta.uid() != 0 && meta.uid() != euid) || meta.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} may be changed by other users", dir.display()),
            ));
        }
    }
    Ok(resolved)
}

/// Writes the checked bytes into a directory made new for this process under `temp`.
#[cfg(any(not(target_os = "linux"), test))]
fn stage(bytes: &[u8], temp: &Path) -> io::Result<std::path::PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = temp.join(format!("{STAGE_PREFIX}{}-{stamp}", std::process::id()));
    private_dir(&dir)?;
    let copy = dir.join(crate::LIBRARY_NAME);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&copy)?
        .write_all(bytes)?;
    Ok(copy)
}

/// Copies other starts left, once this one loaded its own (`keep`). A copy another process
/// staged and has yet to load goes too, and that process then fails to load: it takes two
/// processes loading for the first time at once. A copy another process has loaded stays
/// mapped on Unix; on Windows it cannot be removed and goes at a later start.
#[cfg(any(not(target_os = "linux"), test))]
fn remove_stale(temp: &Path, keep: Option<&Path>) {
    let Ok(entries) = fs::read_dir(temp) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(STAGE_PREFIX));
        if ours && Some(entry.path().as_path()) != keep && owned(&entry.path()) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(all(unix, any(not(target_os = "linux"), test)))]
fn owned(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.is_dir() && meta.uid() == unsafe { libc::geteuid() })
}

#[cfg(all(unix, any(not(target_os = "linux"), test)))]
fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(windows)]
fn owned(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// A protected DACL for SYSTEM, Administrators and the directory's owner, inherited by the copy:
/// the rights FlClash's Helper requires of its own install directory.
#[cfg(windows)]
fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)\0"
        .encode_utf16()
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and `descriptor` receives a LocalAlloc'd descriptor,
    // freed below.
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if parsed == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is NUL-terminated and `attributes` points to a live descriptor.
    let made = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    let err = io::Error::last_os_error();
    // SAFETY: `descriptor` came from the conversion above and is not used after this.
    unsafe { LocalFree(descriptor) };
    if made == 0 { Err(err) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_library_that_does_not_match_its_pin_is_refused() {
        let bytes = b"not the library";
        let pin = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(matches!(
            check(Path::new("lib"), bytes, pin, false),
            Err(LoadError::Mismatch { found: Some(_), .. })
        ));
        assert!(matches!(
            check(Path::new("lib"), bytes, pin, true),
            Err(LoadError::Mismatch { found: None, .. })
        ));
        assert!(check(Path::new("lib"), b"", pin, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn only_a_regular_file_is_read_as_the_library() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = temp.path().join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.unwrap().success());
        assert!(read_file(&fifo).is_err());
        assert!(read_file(temp.path()).is_err());
        let file = temp.path().join("lib");
        fs::write(&file, b"library").unwrap();
        assert_eq!(read_file(&file).unwrap(), b"library");
    }

    #[test]
    fn a_copy_lands_in_a_fresh_private_directory_and_old_ones_go_once_it_is_loaded() {
        let temp = tempfile::tempdir().unwrap();
        let stale = temp.path().join(format!("{STAGE_PREFIX}1"));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join(crate::LIBRARY_NAME), b"old").unwrap();
        let unrelated = temp.path().join("other");
        fs::create_dir(&unrelated).unwrap();

        let copy = stage(b"library", temp.path()).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), b"library");
        assert!(stale.exists(), "a copy goes only once this one is loaded");
        remove_stale(temp.path(), copy.parent());
        assert!(!stale.exists() && unrelated.exists() && copy.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(copy.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        let again = stage(b"again", temp.path()).unwrap();
        assert!(copy.exists(), "staging leaves another start's copy alone");
        remove_stale(temp.path(), again.parent());
        assert!(!copy.exists() && again.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_elevated_copy_is_staged_only_where_nobody_else_may_write_it_or_above_it() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |dir: &Path, mode| fs::set_permissions(dir, fs::Permissions::from_mode(mode));
        let temp = tempfile::tempdir().unwrap();
        let open = temp.path().join("open");
        let inner = open.join("inner");
        fs::create_dir_all(&inner).unwrap();
        mode(&open, 0o777).unwrap();
        mode(&inner, 0o700).unwrap();
        for refused in [&open, &inner] {
            let err = trusted_root(refused).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn only_root_acting_for_a_user_stages_outside_tmpdir_not_setgid_or_another_user() {
        assert!(!concord_platform::is_setuid_elevated());
        assert_eq!(stage_root(false).unwrap(), std::env::temp_dir());
        let own = fs::canonicalize(own_temp_dir().unwrap()).unwrap();
        assert_eq!(stage_root(true).unwrap(), own);
    }
}
