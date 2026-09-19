//! `validated_string!`: a `String` newtype that is correct by construction.
//!
//! Every wire-level string this workspace refuses to pass around bare (a
//! notes ref, a fingerprint, a correlation id, a branch name, ...) has the
//! same shape: one constructor that runs the type's validation, `as_str`,
//! `Display`, `FromStr`, and serde impls that serialise as the bare string
//! and deserialise *through the constructor* so a malformed wire value is
//! rejected at parse time with the validation error's own message. The
//! macro writes that shape once; each type supplies only its validation
//! (and, rarely, a normalisation applied after validation).
//!
//! [`validated_string_laws!`](crate::validated_string_laws) is the matching test: given a strategy of
//! candidate strings it checks, for every candidate, that the constructor
//! agrees with the validation function, that `FromStr` and `Deserialize`
//! agree with the constructor, that `Display`/`Serialize` render the wrapped
//! text exactly, that an accepted value re-parses to itself, and that a
//! rejected wire value's error names the rule it broke.

/// Define a validated `String` newtype.
///
/// ```ignore
/// validated_string! {
///     /// Docs for the type.
///     pub struct NotesRef;
///     error = NotesRefError;
///     constructor = try_new;
///     validate = validate_notes_ref;            // fn(&str) -> Result<(), NotesRefError>
///     // normalise = |s: String| s.to_ascii_lowercase();   (optional; runs after validation)
/// }
/// ```
///
/// The type derives `Clone, Debug, Eq, Hash, PartialEq`; put any further
/// derives in the attribute list before `struct`.
#[macro_export]
macro_rules! validated_string {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
        error = $err:ty;
        constructor = $ctor:ident;
        validate = $validate:expr;
        $(normalise = $normalise:expr;)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        $vis struct $name(String);

        impl $name {
            /// Validate `raw` and wrap it. The rules are the type's own; see
            /// its documentation.
            $vis fn $ctor(raw: impl Into<String>) -> Result<Self, $err> {
                let raw: String = raw.into();
                let validate: fn(&str) -> Result<(), $err> = $validate;
                validate(&raw)?;
                $(
                    let normalise: fn(String) -> String = $normalise;
                    let raw = normalise(raw);
                )?
                Ok(Self(raw))
            }

            $vis fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $err;
            fn from_str(raw: &str) -> Result<Self, Self::Err> {
                Self::$ctor(raw)
            }
        }

        impl $crate::__serde::Serialize for $name {
            fn serialize<S: $crate::__serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> $crate::__serde::Deserialize<'de> for $name {
            fn deserialize<D: $crate::__serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = <String as $crate::__serde::Deserialize>::deserialize(d)?;
                Self::$ctor(raw).map_err($crate::__serde::de::Error::custom)
            }
        }
    };
}

/// The laws every [`validated_string!`] type obeys, as one property test
/// over `$candidates` (a `proptest` strategy of `String`s that should mix
/// accepted and rejected shapes). Invoke inside a `#[cfg(test)]` module of
/// a crate with `proptest` and `serde_json` as dev-dependencies.
///
/// ```ignore
/// validated_string_laws!(NotesRef, try_new, validate_notes_ref, notes_ref_candidates());
/// ```
#[macro_export]
macro_rules! validated_string_laws {
    ($name:ident, $ctor:ident, $validate:expr, $candidates:expr) => {
        ::proptest::proptest! {
            #[test]
            fn validated_string_laws(raw in $candidates) {
                let validate: fn(&str) -> Result<(), _> = $validate;
                let parsed = $name::$ctor(raw.clone());
                ::proptest::prop_assert_eq!(parsed.is_ok(), validate(&raw).is_ok());
                ::proptest::prop_assert_eq!(&raw.parse::<$name>(), &parsed);
                let wire = ::serde_json::to_string(&raw).unwrap();
                match &parsed {
                    Ok(value) => {
                        ::proptest::prop_assert_eq!(value.to_string(), value.as_str());
                        ::proptest::prop_assert_eq!(
                            ::serde_json::to_string(value).unwrap(),
                            ::serde_json::to_string(value.as_str()).unwrap()
                        );
                        ::proptest::prop_assert_eq!(
                            ::serde_json::from_str::<$name>(&wire).unwrap(),
                            value.clone()
                        );
                        ::proptest::prop_assert_eq!(
                            $name::$ctor(value.as_str()),
                            Ok(value.clone()),
                            "an accepted value re-parses to itself"
                        );
                    }
                    Err(err) => {
                        let message = ::serde_json::from_str::<$name>(&wire)
                            .unwrap_err()
                            .to_string();
                        ::proptest::prop_assert!(
                            message.contains(&err.to_string()),
                            "wire rejection {message:?} does not name the rule {err}"
                        );
                    }
                }
            }
        }
    };
}
