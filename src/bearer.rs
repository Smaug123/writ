//! Shared bearer-token syntax checks for the VM broker boundary.

pub(crate) fn is_bearer_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn expected_unreserved_token_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    }

    fn unreserved_token_byte_strategy() -> impl Strategy<Value = u8> {
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'-'),
            Just(b'.'),
            Just(b'_'),
            Just(b'~'),
        ]
    }

    fn non_unreserved_token_byte_strategy() -> impl Strategy<Value = u8> {
        let bytes = (0u8..=u8::MAX)
            .filter(|byte| !expected_unreserved_token_byte(*byte))
            .collect::<Vec<_>>();
        prop::sample::select(bytes)
    }

    proptest! {
        #[test]
        fn bearer_token_byte_accepts_unreserved_ascii(byte in unreserved_token_byte_strategy()) {
            prop_assert!(is_bearer_token_byte(byte), "rejected byte {byte:?}");
        }

        #[test]
        fn bearer_token_byte_rejects_everything_else(byte in non_unreserved_token_byte_strategy()) {
            prop_assert!(!is_bearer_token_byte(byte), "accepted byte {byte:?}");
        }
    }
}
