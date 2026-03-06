/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::io::{Result, Error, ErrorKind};
use std::os::unix::fs::OpenOptionsExt;

/// File system Isolation Guard (Jail)
#[derive(Clone, Debug)]
pub struct Jail {
    root: PathBuf,
}

impl Jail {
    pub fn init<P: AsRef<Path>>(root: P) -> Result<Self> {
        let path = root.as_ref();
        if !path.exists() {
            std::fs::create_dir_all(path)?;
        }
        Self::new(path)
    }

    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_canonical = root.as_ref().canonicalize()?;
        if !root_canonical.is_dir() {
            return Err(Error::new(ErrorKind::InvalidInput, "Jail root must be a directory"));
        }
        Ok(Self { root: root_canonical })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn open_file<P: AsRef<Path>>(&self, path: P) -> Result<File> {
        let mut opts = OpenOptions::new();
        opts.read(true);
        self.secure_open(path, opts)
    }

    pub fn create_file<P: AsRef<Path>>(&self, path: P) -> Result<File> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        self.secure_open(path, opts)
    }

    fn secure_open<P: AsRef<Path>>(&self, path: P, mut options: OpenOptions) -> Result<File> {
        let requested_path = path.as_ref();
        let base_path = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            self.root.join(requested_path)
        };

        let full_path = if base_path.exists() {
            base_path.canonicalize()?
        } else {
            match base_path.parent() {
                Some(parent) if parent.exists() => {
                    let parent_canonical = parent.canonicalize()?;
                    parent_canonical.join(base_path.file_name().unwrap_or_default())
                }
                _ => base_path.clone(),
            }
        };

        if !full_path.starts_with(&self.root) {
            return Err(Error::new(ErrorKind::PermissionDenied, "Access Denied: Path outside of jail"));
        }

        #[cfg(unix)]
        {
            options.custom_flags(libc::O_NOFOLLOW);
        }

        let file = options.open(&full_path)?;
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(ErrorKind::PermissionDenied, "Access Denied: Symbolic link detected after open"));
        }
        
        Ok(file)
    }

    pub fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let requested_path = path.as_ref();
        let full_path = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            self.root.join(requested_path)
        };

        if !full_path.starts_with(&self.root) {
            return Err(Error::new(ErrorKind::PermissionDenied, "Access Denied: Path outside of jail"));
        }

        std::fs::create_dir_all(full_path)
    }

    pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(&self, path: P, contents: C) -> Result<()> {
        let requested_path = path.as_ref();
        let mut file = self.create_file(requested_path)?;
        use std::io::Write;
        file.write_all(contents.as_ref())
    }
}
