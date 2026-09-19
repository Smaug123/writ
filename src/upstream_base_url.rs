//! An `http`/`https` URL that request paths are joined onto: the one parser
//! behind every "upstream base URL" the broker is configured with.
//!
//! The shape is deliberately narrow. Credentials in the URL would be a second,
//! unaudited channel for a secret; a query or fragment would be silently
//! discarded or duplicated by `Url::join`; and a path without a trailing `/`
//! makes `join` *replace* its last segment rather than append to it, so
//! `https://host/v1` + `messages` would quietly become `https://host/messages`.
//! Parsing pins all of that once, so callers hold a value that `join` treats
//! the way they expect.

use std::fmt;

/// An absolute `http`/`https` URL with no credentials, query or fragment,
/// whose path ends in `/`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamBaseUrl(reqwest::Url);

/// Why a string is not an [`UpstreamBaseUrl`]. Each message reads as the
/// continuation of a label the caller supplies (`"Nix cache upstream URL
/// {0}"`), so one wrapping variant per config replaces five.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum UpstreamBaseUrlError {
    #[error("must not be empty")]
    Empty,
    #[error("{raw:?} is invalid: {message}")]
    Invalid { raw: String, message: String },
    #[error("{raw:?} uses unsupported scheme {scheme:?}")]
    UnsupportedScheme { raw: String, scheme: String },
    #[error("must not contain embedded credentials: {0:?}")]
    HasCredentials(String),
    #[error("must not contain a query or fragment: {0:?}")]
    HasQueryOrFragment(String),
}

impl UpstreamBaseUrl {
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, UpstreamBaseUrlError> {
        let raw = raw.as_ref();
        if raw.is_empty() {
            return Err(UpstreamBaseUrlError::Empty);
        }
        let mut url = reqwest::Url::parse(raw).map_err(|err| UpstreamBaseUrlError::Invalid {
            raw: raw.to_string(),
            message: err.to_string(),
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(UpstreamBaseUrlError::UnsupportedScheme {
                raw: raw.to_string(),
                scheme: url.scheme().to_string(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UpstreamBaseUrlError::HasCredentials(raw.to_string()));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(UpstreamBaseUrlError::HasQueryOrFragment(raw.to_string()));
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self(url))
    }

    pub fn as_url(&self) -> &reqwest::Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for UpstreamBaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A URL assembled from parts whose acceptability is known from the
    /// parts alone, so the test can say what the parser *must* answer
    /// rather than re-deriving it with the same library.
    #[derive(Clone, Debug)]
    struct Assembled {
        scheme: &'static str,
        userinfo: Option<String>,
        host: String,
        segments: Vec<String>,
        trailing_slash: bool,
        query: Option<String>,
        fragment: Option<String>,
    }

    impl Assembled {
        fn raw(&self) -> String {
            let mut s = format!("{}://", self.scheme);
            if let Some(userinfo) = &self.userinfo {
                s.push_str(userinfo);
                s.push('@');
            }
            s.push_str(&self.host);
            for segment in &self.segments {
                s.push('/');
                s.push_str(segment);
            }
            if self.trailing_slash {
                s.push('/');
            }
            if let Some(query) = &self.query {
                s.push('?');
                s.push_str(query);
            }
            if let Some(fragment) = &self.fragment {
                s.push('#');
                s.push_str(fragment);
            }
            s
        }

        /// The verdict the parser must reach, and the normalised text it
        /// must hold when it accepts.
        fn expected(&self) -> Result<String, UpstreamBaseUrlError> {
            let raw = self.raw();
            if !matches!(self.scheme, "http" | "https") {
                return Err(UpstreamBaseUrlError::UnsupportedScheme {
                    raw,
                    scheme: self.scheme.to_string(),
                });
            }
            if self.userinfo.is_some() {
                return Err(UpstreamBaseUrlError::HasCredentials(raw));
            }
            if self.query.is_some() || self.fragment.is_some() {
                return Err(UpstreamBaseUrlError::HasQueryOrFragment(raw));
            }
            let mut path = self
                .segments
                .iter()
                .fold(String::new(), |mut acc, segment| {
                    acc.push('/');
                    acc.push_str(segment);
                    acc
                });
            path.push('/');
            Ok(format!("{}://{}{}", self.scheme, self.host, path))
        }
    }

    fn word() -> impl Strategy<Value = String> {
        "[a-z0-9]{1,8}"
    }

    fn assembled() -> impl Strategy<Value = Assembled> {
        (
            prop_oneof![
                4 => Just("https"),
                3 => Just("http"),
                1 => Just("ftp"),
                1 => Just("ssh"),
            ],
            prop::option::weighted(
                0.2,
                prop_oneof![
                    word(),
                    (word(), word()).prop_map(|(u, p)| format!("{u}:{p}"))
                ],
            ),
            prop_oneof![
                Just("127.0.0.1".to_string()),
                word().prop_map(|w| format!("{w}.example.test")),
            ],
            prop::collection::vec(word(), 0..4),
            any::<bool>(),
            prop::option::weighted(0.2, word()),
            prop::option::weighted(0.2, word()),
        )
            .prop_map(
                |(scheme, userinfo, host, segments, trailing_slash, query, fragment)| Assembled {
                    scheme,
                    userinfo,
                    host,
                    segments,
                    trailing_slash,
                    query,
                    fragment,
                },
            )
    }

    proptest! {
        /// The parser accepts exactly the assembled URLs the spec says it
        /// should, names the first rule broken, and normalises the accepted
        /// ones to a `/`-terminated path.
        #[test]
        fn accepts_exactly_the_specified_shape(assembled in assembled()) {
            let result = UpstreamBaseUrl::parse(assembled.raw());
            prop_assert_eq!(result.map(|url| url.as_str().to_string()), assembled.expected());
        }

        /// Whatever text comes in, an accepted value satisfies every rule on
        /// inspection, and re-parsing its text is the identity.
        #[test]
        fn accepted_values_are_fixed_points(raw in ".{0,64}") {
            if let Ok(url) = UpstreamBaseUrl::parse(&raw) {
                let inner = url.as_url();
                prop_assert!(matches!(inner.scheme(), "http" | "https"));
                prop_assert!(inner.username().is_empty() && inner.password().is_none());
                prop_assert!(inner.query().is_none() && inner.fragment().is_none());
                prop_assert!(inner.path().ends_with('/'));
                prop_assert_eq!(UpstreamBaseUrl::parse(url.as_str()), Ok(url));
            }
        }
    }

    #[test]
    fn rejects_empty_and_unparseable_text() {
        assert_eq!(UpstreamBaseUrl::parse(""), Err(UpstreamBaseUrlError::Empty));
        assert!(matches!(
            UpstreamBaseUrl::parse("example.test"),
            Err(UpstreamBaseUrlError::Invalid { .. })
        ));
        assert!(matches!(
            UpstreamBaseUrl::parse("not a url"),
            Err(UpstreamBaseUrlError::Invalid { .. })
        ));
    }

    #[test]
    fn a_trailing_slash_makes_join_append() {
        let base = UpstreamBaseUrl::parse("https://proxy.example.test/anthropic").unwrap();
        assert_eq!(base.as_str(), "https://proxy.example.test/anthropic/");
        assert_eq!(
            base.as_url().join("v1/messages").unwrap().as_str(),
            "https://proxy.example.test/anthropic/v1/messages"
        );
    }
}
