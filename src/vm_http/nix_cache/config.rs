//! Configuration for the VM-facing Nix binary-cache proxy: the validated,
//! normalised upstream URL, the metadata/NAR byte bounds, the trusted signing
//! keys, and the optional local flake-input archive served local-first.

use std::path::PathBuf;

use writ_core::byte_size::ByteSize;

use crate::nix_binary_cache::NixTrustedPublicKeys;
use crate::upstream_base_url::{UpstreamBaseUrl, UpstreamBaseUrlError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpNixCacheConfig {
    upstream_base_url: UpstreamBaseUrl,
    max_metadata_bytes: ByteSize,
    max_nar_bytes: ByteSize,
    trusted_public_keys: NixTrustedPublicKeys,
    /// The broker's local archives, served *local-first* and in order ahead of
    /// the upstream proxy: for a requested hash the first dir holding a
    /// `<hash>.narinfo` is authoritative (admitting it content-addressed-unsigned
    /// or trusted-signed; see `parse_local_admissible_narinfo_for_store_hash`),
    /// and only a miss in *every* dir falls through to the upstream. Empty (the
    /// default) leaves behaviour identical to a pure upstream proxy.
    ///
    /// Ordered pre-warm-first: a durable, operator-managed pre-warmed closure
    /// cache ahead of the auto-provisioned, content-addressed flake-input cache.
    local_cache_dirs: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum VmHttpNixCacheConfigError {
    #[error("Nix cache upstream URL {0}")]
    UpstreamUrl(#[from] UpstreamBaseUrlError),
    #[error("Nix cache max metadata bytes must be greater than zero")]
    EmptyMaxMetadataBytes,
    #[error("Nix cache max NAR bytes must be greater than zero")]
    EmptyMaxNarBytes,
}

impl VmHttpNixCacheConfig {
    pub fn new(
        upstream_base_url: impl AsRef<str>,
        max_metadata_bytes: ByteSize,
        max_nar_bytes: ByteSize,
    ) -> Result<Self, VmHttpNixCacheConfigError> {
        Self::new_with_trusted_public_keys(
            upstream_base_url,
            max_metadata_bytes,
            max_nar_bytes,
            NixTrustedPublicKeys::empty(),
        )
    }

    pub fn new_with_trusted_public_keys(
        upstream_base_url: impl AsRef<str>,
        max_metadata_bytes: ByteSize,
        max_nar_bytes: ByteSize,
        trusted_public_keys: NixTrustedPublicKeys,
    ) -> Result<Self, VmHttpNixCacheConfigError> {
        let upstream_base_url = UpstreamBaseUrl::parse(upstream_base_url)?;
        if max_metadata_bytes.is_zero() {
            return Err(VmHttpNixCacheConfigError::EmptyMaxMetadataBytes);
        }
        if max_nar_bytes.is_zero() {
            return Err(VmHttpNixCacheConfigError::EmptyMaxNarBytes);
        }
        Ok(Self {
            upstream_base_url,
            max_metadata_bytes,
            max_nar_bytes,
            trusted_public_keys,
            local_cache_dirs: Vec::new(),
        })
    }

    /// Trust `keys` when verifying signed narinfos, replacing whatever
    /// [`Self::new`] left in place.
    ///
    /// The builder form exists so a caller validating a whole config can check
    /// the URL and the key list as *independent* inputs and report both
    /// failures, rather than being forced to have parsed the keys before it may
    /// even attempt the URL.
    #[must_use]
    pub fn with_trusted_public_keys(mut self, trusted_public_keys: NixTrustedPublicKeys) -> Self {
        self.trusted_public_keys = trusted_public_keys;
        self
    }

    /// Serve the broker's local archives `dirs` local-first, in order (see
    /// [`VmHttpNixCacheConfig::local_cache_dirs`]). An empty vec disables local
    /// serving. The directories need not exist yet — an absent dir is treated as
    /// a local miss, so behaviour is identical to upstream-only until one is
    /// populated.
    #[must_use]
    pub fn with_local_cache_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.local_cache_dirs = dirs;
        self
    }

    pub fn upstream_base_url(&self) -> &UpstreamBaseUrl {
        &self.upstream_base_url
    }

    pub fn local_cache_dirs(&self) -> &[PathBuf] {
        &self.local_cache_dirs
    }

    pub fn max_metadata_bytes(&self) -> ByteSize {
        self.max_metadata_bytes
    }

    pub fn max_nar_bytes(&self) -> ByteSize {
        self.max_nar_bytes
    }

    pub fn trusted_public_keys(&self) -> &NixTrustedPublicKeys {
        &self.trusted_public_keys
    }
}
