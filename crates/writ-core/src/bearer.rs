//! Shared bearer-token syntax checks for the VM broker boundary.

pub fn is_bearer_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RFC 3986 `unreserved`, written out as the ranges the grammar lists
    /// (`ALPHA / DIGIT / "-" / "." / "_" / "~"`) rather than as a predicate,
    /// so this cannot agree with the function under test by construction.
    fn unreserved_bytes() -> Vec<u8> {
        (b'a'..=b'z')
            .chain(b'A'..=b'Z')
            .chain(b'0'..=b'9')
            .chain([b'-', b'.', b'_', b'~'])
            .collect()
    }

    proptest! {
        /// Over every byte value, the predicate agrees with the enumerated
        /// set, on both sides.
        #[test]
        fn bearer_token_byte_is_exactly_rfc3986_unreserved(byte in any::<u8>()) {
            prop_assert_eq!(
                is_bearer_token_byte(byte),
                unreserved_bytes().contains(&byte),
                "byte {:?}",
                byte
            );
        }
    }

    #[test]
    fn the_unreserved_set_has_sixty_six_members() {
        // 26 + 26 + 10 + 4: a typo in the enumeration would change this.
        assert_eq!(unreserved_bytes().len(), 66);
    }
}
