//! Shared atomic file replacement: create the parent, write a unique
//! sibling temp file, fsync it, then rename over the destination.
//!
//! Callers map the `io::Error` to their own typed error so module-specific
//! messages and stable codes stay unchanged.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tempfile::NamedTempFile;

pub(crate) fn write_atomic(destination: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    Ok(())
}
