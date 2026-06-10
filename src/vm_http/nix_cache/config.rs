//! Configuration for the VM-facing Nix binary-cache proxy: the validated,
//! normalised upstream URL, the metadata/NAR byte bounds, the trusted signing
//! keys, and the optional local flake-input archive served local-first.

use std::path::PathBuf;

use crate::nix_cache::NixTrustedPublicKeys;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmHttpNixCacheConfig {
    upstream_base_url: reqwest::Url,
    max_metadata_bytes: u64,
    max_nar_bytes: u64,
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
    #[error("Nix cache upstream URL must not be empty")]
    EmptyUpstreamUrl,
    #[error("Nix cache upstream URL {raw:?} is invalid: {message}")]
    InvalidUpstreamUrl { raw: String, message: String },
    #[error("Nix cache upstream URL {raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedUpstreamScheme { raw: String, scheme: String },
    #[error("Nix cache upstream URL must not contain embedded credentials: {0:?}")]
    UpstreamUrlHasCredentials(String),
    #[error("Nix cache upstream URL must not contain a query or fragment: {0:?}")]
    UpstreamUrlHasQueryOrFragment(String),
    #[error("Nix cache max metadata bytes must be greater than zero")]
    EmptyMaxMetadataBytes,
    #[error("Nix cache max NAR bytes must be greater than zero")]
    EmptyMaxNarBytes,
}

impl VmHttpNixCacheConfig {
    pub fn new(
        upstream_base_url: impl AsRef<str>,
        max_metadata_bytes: u64,
        max_nar_bytes: u64,
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
        max_metadata_bytes: u64,
        max_nar_bytes: u64,
        trusted_public_keys: NixTrustedPublicKeys,
    ) -> Result<Self, VmHttpNixCacheConfigError> {
        let raw = upstream_base_url.as_ref();
        if raw.is_empty() {
            return Err(VmHttpNixCacheConfigError::EmptyUpstreamUrl);
        }
        if max_metadata_bytes == 0 {
            return Err(VmHttpNixCacheConfigError::EmptyMaxMetadataBytes);
        }
        if max_nar_bytes == 0 {
            return Err(VmHttpNixCacheConfigError::EmptyMaxNarBytes);
        }
        let mut url = reqwest::Url::parse(raw).map_err(|err| {
            VmHttpNixCacheConfigError::InvalidUpstreamUrl {
                raw: raw.to_string(),
                message: err.to_string(),
            }
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(VmHttpNixCacheConfigError::UnsupportedUpstreamScheme {
                raw: raw.to_string(),
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(VmHttpNixCacheConfigError::UpstreamUrlHasCredentials(
                raw.to_string(),
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(VmHttpNixCacheConfigError::UpstreamUrlHasQueryOrFragment(
                raw.to_string(),
            ));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self {
            upstream_base_url: url,
            max_metadata_bytes,
            max_nar_bytes,
            trusted_public_keys,
            local_cache_dirs: Vec::new(),
        })
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

    pub fn upstream_base_url(&self) -> &reqwest::Url {
        &self.upstream_base_url
    }

    pub fn local_cache_dirs(&self) -> &[PathBuf] {
        &self.local_cache_dirs
    }

    pub fn max_metadata_bytes(&self) -> u64 {
        self.max_metadata_bytes
    }

    pub fn max_nar_bytes(&self) -> u64 {
        self.max_nar_bytes
    }

    pub fn trusted_public_keys(&self) -> &NixTrustedPublicKeys {
        &self.trusted_public_keys
    }
}
