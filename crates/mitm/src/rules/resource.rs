use std::path::{Component, Path, PathBuf};

use bytes::Bytes;
use concord_config::mitm::LineError;
use concord_config::mitm::text::quote;
use sha2::{Digest, Sha256};

use super::LOCAL_PIECE;

/// A `map-local` or `request-body-mock` body.
#[derive(Debug, Clone)]
pub enum LocalBody {
    Bytes(Bytes),
    /// A file in the resources directory larger than [LOCAL_PIECE], read at each answer.
    File(PathBuf),
}

#[cfg(test)]
impl LocalBody {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            LocalBody::Bytes(bytes) => bytes,
            LocalBody::File(_) => &[],
        }
    }
}

fn is_local(name: &str) -> bool {
    if name.is_empty() || name.contains('\\') {
        return false;
    }
    let mut depth: i32 = 0;
    for component in Path::new(name).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            _ => return false,
        }
    }
    depth > 0
}

pub(crate) fn read_resource(dir: &Path, param: &str, name: &str) -> Result<Vec<u8>, LineError> {
    let (path, _) = resource_file(dir, param, name)?;
    std::fs::read(&path)
        .map_err(|_| LineError::resource(format!("{param} {} cannot be read", quote(name))))
}

pub(crate) fn read_resource_seen(
    dir: &Path,
    param: &str,
    name: &str,
) -> Result<(Vec<u8>, ResourceSeen), LineError> {
    let bytes = read_resource(dir, param, name)?;
    let digest = ResourceSeen::Content(Sha256::digest(&bytes).into());
    Ok((bytes, digest))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileKind {
    Whole,
    LocalRaw,
}

/// A resource file that compiling a section consulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileRef {
    pub(crate) param: &'static str,
    pub(crate) name: String,
    pub(crate) kind: FileKind,
}

impl FileRef {
    pub(crate) fn new(param: &'static str, name: &str, kind: FileKind) -> Self {
        FileRef {
            param,
            name: name.to_string(),
            kind,
        }
    }

    pub(crate) fn live(&self, dir: &Path) -> Result<ResourceSeen, LineError> {
        match self.kind {
            FileKind::Whole => resource_digest(dir, self.param, &self.name),
            FileKind::LocalRaw => local_file_seen(dir, &self.name),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileRecord {
    pub(crate) file: FileRef,
    pub(crate) seen: Result<ResourceSeen, LineError>,
}

/// What compiling a section took from one of its files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResourceSeen {
    /// The SHA-256 of a file the compile reads whole.
    Content([u8; 32]),
    /// A `map-local` file larger than [LOCAL_PIECE]: each answer reads it from disk, so its
    /// content is not part of what the compile made.
    ReadAtAnswer,
}

/// What [read_resource] finds of `name` now, hashed piece by piece, or why it cannot be read.
pub(crate) fn resource_digest(
    dir: &Path,
    param: &str,
    name: &str,
) -> Result<ResourceSeen, LineError> {
    let (path, _) = resource_file(dir, param, name)?;
    digest_file(&path)
        .map(ResourceSeen::Content)
        .map_err(|_| LineError::resource(format!("{param} {} cannot be read", quote(name))))
}

fn local_seen(
    path: &Path,
    len: u64,
    load: impl FnOnce(&Path) -> std::io::Result<ResourceSeen>,
) -> std::io::Result<ResourceSeen> {
    if len <= LOCAL_PIECE as u64 {
        return load(path);
    }
    std::fs::File::open(path)?;
    Ok(ResourceSeen::ReadAtAnswer)
}

/// As [resource_digest] for a raw `map-local` file, whose content counts only while
/// [local_file] keeps it in memory.
pub(crate) fn local_file_seen(dir: &Path, name: &str) -> Result<ResourceSeen, LineError> {
    let (path, len) = resource_file(dir, "data", name)?;
    local_seen(&path, len, |path| {
        digest_file(path).map(ResourceSeen::Content)
    })
    .map_err(|_| LineError::resource(format!("data {} cannot be read", quote(name))))
}

fn digest_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut piece = vec![0; LOCAL_PIECE];
    loop {
        match std::io::Read::read(&mut file, &mut piece) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(read) => hasher.update(piece.get(..read).unwrap_or_default()),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// The path and length of a regular file in the resources directory.
fn resource_file(dir: &Path, param: &str, name: &str) -> Result<(PathBuf, u64), LineError> {
    if name.contains("://") {
        return Err(LineError::resource(format!(
            "{param} {} has not been downloaded",
            quote(name)
        )));
    }
    if !is_local(name) {
        return Err(LineError::resource(format!(
            "{param} {} is not a file in the resources directory",
            quote(name)
        )));
    }
    let map_io = |err: std::io::Error| {
        let reason = match err.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            _ => "cannot be read".to_string(),
        };
        LineError::resource(format!("{param} {}: {reason}", quote(name)))
    };
    let canonical_dir = std::fs::canonicalize(dir).map_err(map_io)?;
    let path = dir.join(name);
    let canonical_path = std::fs::canonicalize(&path).map_err(map_io)?;
    if !canonical_path.starts_with(&canonical_dir) {
        return Err(LineError::resource(format!(
            "{param} {} is not a file in the resources directory",
            quote(name)
        )));
    }
    let info = std::fs::metadata(&canonical_path).map_err(map_io)?;
    if !info.is_file() {
        return Err(LineError::resource(format!(
            "{param} {} is not a regular file",
            quote(name)
        )));
    }
    Ok((path, info.len()))
}

pub(super) fn local_file(dir: &Path, name: &str) -> Result<(LocalBody, ResourceSeen), LineError> {
    let (path, len) = resource_file(dir, "data", name)?;
    let mut body = None;
    let seen = local_seen(&path, len, |path| {
        let bytes = std::fs::read(path)?;
        let digest = Sha256::digest(&bytes).into();
        body = Some(LocalBody::Bytes(bytes.into()));
        Ok(ResourceSeen::Content(digest))
    })
    .map_err(|_| LineError::resource(format!("data {} cannot be read", quote(name))))?;
    Ok((body.unwrap_or(LocalBody::File(path)), seen))
}
