//! Example tests for [`VmHttpNixCacheConfig`] URL normalisation and the
//! unsafe-shape rejections its constructor enforces.

use super::*;

#[test]
fn nix_cache_config_normalizes_base_urls_and_rejects_unsafe_shapes() {
    let config = VmHttpNixCacheConfig::new("https://cache.example.test/base", 1024, 2048).unwrap();
    assert_eq!(
        config.upstream_base_url().as_str(),
        "https://cache.example.test/base/"
    );

    assert_eq!(
        VmHttpNixCacheConfig::new("", 1024, 2048),
        Err(VmHttpNixCacheConfigError::EmptyUpstreamUrl)
    );
    assert_eq!(
        VmHttpNixCacheConfig::new("https://cache.example.test", 0, 2048),
        Err(VmHttpNixCacheConfigError::EmptyMaxMetadataBytes)
    );
    assert_eq!(
        VmHttpNixCacheConfig::new("https://cache.example.test", 1024, 0),
        Err(VmHttpNixCacheConfigError::EmptyMaxNarBytes)
    );
    assert!(matches!(
        VmHttpNixCacheConfig::new("file:///nix/store", 1024, 2048),
        Err(VmHttpNixCacheConfigError::UnsupportedUpstreamScheme { .. })
    ));
    assert!(matches!(
        VmHttpNixCacheConfig::new("https://user:pass@cache.example.test", 1024, 2048),
        Err(VmHttpNixCacheConfigError::UpstreamUrlHasCredentials(_))
    ));
    assert!(matches!(
        VmHttpNixCacheConfig::new("https://cache.example.test?x=1", 1024, 2048),
        Err(VmHttpNixCacheConfigError::UpstreamUrlHasQueryOrFragment(_))
    ));
}
