//! The two text checks every configured directory gets before anything
//! touches the filesystem: the path is not empty, and it is absolute.
//!
//! Configured paths are read from files whose author may have left a key
//! blank or written a path relative to wherever they happened to be; the
//! daemon runs from `/` and would resolve such a path somewhere the author
//! never meant. The check is pure so a config can be rejected on its text
//! alone, before any directory is created, and it names the field so the
//! message says which key to fix.

use std::path::{Path, PathBuf};

/// Why a configured path is unusable before the filesystem is consulted.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum PathShapeError {
    #[error("{field} path must not be empty")]
    Empty { field: &'static str },
    #[error("{field} path must be absolute: {path:?}")]
    Relative { field: &'static str, path: PathBuf },
}

/// Accept `path` if it is non-empty, naming `field` otherwise. For a program
/// name that may legitimately be resolved through `PATH`.
pub fn require_non_empty(field: &'static str, path: &Path) -> Result<(), PathShapeError> {
    if path.as_os_str().is_empty() {
        return Err(PathShapeError::Empty { field });
    }
    Ok(())
}

/// Accept `path` if it is non-empty and absolute, naming `field` otherwise.
pub fn require_absolute(field: &'static str, path: &Path) -> Result<(), PathShapeError> {
    require_non_empty(field, path)?;
    if !path.is_absolute() {
        return Err(PathShapeError::Relative {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Exactly the non-empty absolute paths are accepted; an empty path
        /// is `Empty`, and any other relative path comes back in `Relative`
        /// unchanged so the message can show it.
        #[test]
        fn accepts_exactly_the_non_empty_absolute_paths(
            raw in prop_oneof![Just(String::new()), "/?[a-z./ -]{0,24}", any::<String>()],
        ) {
            let path = Path::new(&raw);
            let expected = if raw.is_empty() {
                Err(PathShapeError::Empty { field: "key" })
            } else if !path.is_absolute() {
                Err(PathShapeError::Relative { field: "key", path: path.to_path_buf() })
            } else {
                Ok(())
            };
            prop_assert_eq!(require_absolute("key", path), expected);
        }
    }
}
