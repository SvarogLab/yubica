use std::path::PathBuf;

use crate::error::AppError;

#[derive(Clone, Debug)]
pub struct OutputPlan {
    dir: PathBuf,
    filename: String,
}

impl OutputPlan {
    pub fn new(dir: impl Into<PathBuf>, filename: impl Into<String>) -> Result<Self, AppError> {
        let dir = dir.into();
        if !dir.exists() {
            return Err(AppError::InvalidIoPath(format!(
                "directory does not exist: {}",
                dir.display()
            )));
        }

        if !dir.is_dir() {
            return Err(AppError::InvalidIoPath(format!(
                "path is not a directory: {}",
                dir.display()
            )));
        }

        let filename = filename.into();
        if filename.trim().is_empty() {
            return Err(AppError::InvalidIoPath("filename must not be empty".into()));
        }

        Ok(Self { dir, filename })
    }

    pub fn crt_path(&self) -> PathBuf {
        self.with_extension("crt")
    }

    pub fn key_path(&self) -> PathBuf {
        self.with_extension("key")
    }

    pub fn csr_path(&self) -> PathBuf {
        self.with_extension("csr")
    }

    fn with_extension(&self, extension: &str) -> PathBuf {
        self.dir.join(format!("{}.{}", self.filename, extension))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("yubica-io-test-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn paths_join_dir_filename_and_extension() {
        let dir = TempDir::new();
        let plan = OutputPlan::new(dir.0.clone(), "offline-root-ca").unwrap();
        assert_eq!(plan.crt_path(), dir.0.join("offline-root-ca.crt"));
        assert_eq!(plan.key_path(), dir.0.join("offline-root-ca.key"));
        assert_eq!(plan.csr_path(), dir.0.join("offline-root-ca.csr"));
    }

    #[test]
    fn rejects_missing_directory() {
        let dir = TempDir::new();
        let missing = dir.0.join("does-not-exist");
        assert!(OutputPlan::new(missing, "name").is_err());
    }

    #[test]
    fn rejects_path_that_is_not_a_directory() {
        let dir = TempDir::new();
        let file = dir.0.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(OutputPlan::new(file, "name").is_err());
    }

    #[test]
    fn rejects_empty_filename() {
        let dir = TempDir::new();
        assert!(OutputPlan::new(dir.0.clone(), "   ").is_err());
    }
}
