//! Bounded, fail-closed reads of the broker's local flake-input archive. These
//! primitives never trust the on-disk object: the open refuses symlinks and
//! FIFOs, requires a regular file, and hard-caps the byte budget so a file that
//! grows or is swapped after classification cannot blow the bound.

use std::path::Path;
use writ_core::byte_size::ByteSize;

/// Outcome of a bounded read of a local-archive file.
pub(super) enum LocalCacheFile {
    /// No such file (or not a regular file) — a local miss; the caller proxies
    /// upstream.
    Missing,
    /// The file exceeds the configured byte bound; fail closed.
    TooLarge,
    /// An unexpected I/O error reading a file that exists; fail closed.
    Io(std::io::Error),
    Bytes(Vec<u8>),
}

/// `lstat` of a local-archive entry, classifying it without opening anything.
enum LocalCacheLstat {
    /// Absent, or not a *regular* file (a symlink, FIFO, directory, socket, …).
    /// Treated as a miss.
    Missing,
    Io(std::io::Error),
    /// A regular file of this byte length.
    RegularFile {
        len: u64,
    },
}

/// `lstat` a local-archive entry and require it be a *regular* file. Used by the
/// HEAD path, which only needs the length and never opens the entry, so it can
/// neither block on a FIFO nor follow a symlink. A Nix file cache holds only
/// regular files; symlinks/FIFOs/dirs are reported as a miss.
async fn lstat_local_cache_file(path: &Path) -> LocalCacheLstat {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_file() => LocalCacheLstat::RegularFile {
            len: metadata.len(),
        },
        Ok(_) => LocalCacheLstat::Missing,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => LocalCacheLstat::Missing,
        Err(err) => LocalCacheLstat::Io(err),
    }
}

/// Read a local-archive file, enforcing `max` fail-closed and mapping an absent
/// (or non-regular) file to [`LocalCacheFile::Missing`] so the caller can fall
/// through to the upstream. Then read hard-capped at `max + 1` bytes — never
/// buffering the whole file first — so the bound holds unconditionally even if
/// the file grows after it is opened.
///
/// The open closes the classify/open race a bare `lstat` would leave: `O_NOFOLLOW`
/// refuses a final-component symlink (so a swapped-in link cannot redirect the
/// read outside the cache dir), `O_NONBLOCK` makes opening a FIFO return
/// immediately instead of blocking the request, and the held fd is then `fstat`'d
/// to require a *regular* file — validating the object actually opened, not a
/// name re-stat. A Nix file cache holds only regular files, so this rejects
/// nothing legitimate.
pub(super) async fn read_local_cache_file(path: &Path, max: ByteSize) -> LocalCacheFile {
    use tokio::io::AsyncReadExt as _;

    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .await
    {
        Ok(file) => file,
        // Absent, or a final-component symlink refused by `O_NOFOLLOW` (ELOOP):
        // a local miss. (`ErrorKind::FilesystemLoop` is still unstable, so match
        // the errno directly.)
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.raw_os_error() == Some(libc::ELOOP) =>
        {
            return LocalCacheFile::Missing;
        }
        Err(err) => return LocalCacheFile::Io(err),
    };
    match file.metadata().await {
        // `fstat` on the held fd: only a regular file is served. A FIFO/socket/
        // device that `O_NONBLOCK` let us open, or a directory, is a miss.
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return LocalCacheFile::Missing,
        Err(err) => return LocalCacheFile::Io(err),
    }
    // Read at most `max + 1` bytes: reaching the cap means the file is over
    // budget, without ever holding more than `max + 1` bytes in memory.
    let cap = max.saturating_add(ByteSize::from_bytes(1));
    let mut body = Vec::new();
    if let Err(err) = file.take(cap.get()).read_to_end(&mut body).await {
        return LocalCacheFile::Io(err);
    }
    if ByteSize::of(body.len()) > max {
        return LocalCacheFile::TooLarge;
    }
    LocalCacheFile::Bytes(body)
}

/// Outcome of a bounded *stat* of a local-archive file — its length without
/// reading the body. Used to answer a NAR `HEAD` without buffering the (large)
/// payload.
pub(super) enum LocalCacheStat {
    Missing,
    TooLarge,
    Io(std::io::Error),
    Len(u64),
}

/// Stat a local-archive file, enforcing `max` fail-closed and mapping an absent
/// (or non-regular, including symlink) file to [`LocalCacheStat::Missing`].
/// Returns the byte length without opening the body.
pub(super) async fn stat_local_cache_file(path: &Path, max: ByteSize) -> LocalCacheStat {
    match lstat_local_cache_file(path).await {
        LocalCacheLstat::Missing => LocalCacheStat::Missing,
        LocalCacheLstat::Io(err) => LocalCacheStat::Io(err),
        LocalCacheLstat::RegularFile { len } if ByteSize::from_bytes(len) > max => {
            LocalCacheStat::TooLarge
        }
        LocalCacheLstat::RegularFile { len } => LocalCacheStat::Len(len),
    }
}

/// The `file://` URL recorded as the (non-HTTP) source of a local serve, so the
/// audit log distinguishes a local-archive hit from an upstream proxy.
pub(super) fn local_file_url(path: &Path) -> String {
    format!("file://{}", path.display())
}
