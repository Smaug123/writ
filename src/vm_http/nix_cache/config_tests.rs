//! Example tests for [`VmHttpNixCacheConfig`] URL normalisation and the
//! unsafe-shape rejections its constructor enforces.

use super::*;

#[test]
fn nix_cache_config_normalizes_base_urls_and_rejects_unsafe_shapes() {
    let config = VmHttpNixCacheConfig::new(
        "https://cache.example.test/base",
        ByteSize::kib(1),
        ByteSize::from_bytes(2048),
    )
    .unwrap();
    assert_eq!(
        config.upstream_base_url().as_str(),
        "https://cache.example.test/base/"
    );

    assert_eq!(
        VmHttpNixCacheConfig::new("", ByteSize::kib(1), ByteSize::from_bytes(2048)),
        Err(VmHttpNixCacheConfigError::EmptyUpstreamUrl)
    );
    assert_eq!(
        VmHttpNixCacheConfig::new(
            "https://cache.example.test",
            ByteSize::from_bytes(0),
            ByteSize::from_bytes(2048)
        ),
        Err(VmHttpNixCacheConfigError::EmptyMaxMetadataBytes)
    );
    assert_eq!(
        VmHttpNixCacheConfig::new(
            "https://cache.example.test",
            ByteSize::kib(1),
            ByteSize::from_bytes(0)
        ),
        Err(VmHttpNixCacheConfigError::EmptyMaxNarBytes)
    );
    assert!(matches!(
        VmHttpNixCacheConfig::new(
            "file:///nix/store",
            ByteSize::kib(1),
            ByteSize::from_bytes(2048)
        ),
        Err(VmHttpNixCacheConfigError::UnsupportedUpstreamScheme { .. })
    ));
    assert!(matches!(
        VmHttpNixCacheConfig::new(
            "https://user:pass@cache.example.test",
            ByteSize::kib(1),
            ByteSize::from_bytes(2048)
        ),
        Err(VmHttpNixCacheConfigError::UpstreamUrlHasCredentials(_))
    ));
    assert!(matches!(
        VmHttpNixCacheConfig::new(
            "https://cache.example.test?x=1",
            ByteSize::kib(1),
            ByteSize::from_bytes(2048)
        ),
        Err(VmHttpNixCacheConfigError::UpstreamUrlHasQueryOrFragment(_))
    ));
}
