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

pub(crate) fn open(path: &Path) -> Result<Opened, LoadError> {
    let Some(pinned) = PINNED else {
        // SAFETY: the library is Concord's own Go build; loading runs the Go runtime's
        // initialisers, which start its threads and touch no state of this process.
        return Ok(match unsafe { libloading::Library::new(path) } {
            Ok(lib) => Opened::Loaded(lib),
            Err(err) => Opened::Missing(format!("{}: {err}", path.display())),
        });
    };
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(Opened::Missing(format!("{}: {err}", path.display()))),
    };
    check(path, &bytes, pinned)?;
    load(&bytes, &std::env::temp_dir())
        .map(Opened::Loaded)
        .map_err(|err| LoadError::Stage(err.to_string()))
}

fn check(path: &Path, bytes: &[u8], pinned: &'static str) -> Result<(), LoadError> {
    let found: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if found.eq_ignore_ascii_case(pinned) {
        return Ok(());
    }
    Err(LoadError::Mismatch {
        path: path.display().to_string(),
        found,
        pinned,
    })
}

#[cfg(target_os = "linux")]
fn load(bytes: &[u8], _temp: &Path) -> io::Result<libloading::Library> {
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
fn load(bytes: &[u8], temp: &Path) -> io::Result<libloading::Library> {
    let copy = stage(bytes, temp)?;
    // SAFETY: as in `open`; the copy is the checked library in a directory only this process's
    // user may write.
    let lib = unsafe { libloading::Library::new(&copy) }.map_err(io::Error::other)?;
    remove_stale(temp, copy.parent());
    Ok(lib)
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
            check(Path::new("lib"), bytes, pin),
            Err(LoadError::Mismatch { .. })
        ));
        assert!(check(Path::new("lib"), b"", pin).is_ok());
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
}
