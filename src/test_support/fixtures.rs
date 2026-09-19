//! Key material under `tests/fixtures/`, embedded once. Every fixture is a
//! throwaway test key checked into the repository; none has ever guarded
//! anything.

/// Ed25519 private key in OpenSSH PEM form: the signing identity most tests
/// run writd with.
pub const ED25519_SIGNING_PEM: &str = include_str!("../../tests/fixtures/ed25519_test_signing.key");
/// The public half of [`ED25519_SIGNING_PEM`], in `authorized_keys` form.
pub const ED25519_SIGNING_PUB: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing.key.pub");
/// A second Ed25519 identity, for "signed by someone else" cases.
pub const ED25519_OTHER_PEM: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing_other.key");
/// The public half of [`ED25519_OTHER_PEM`].
pub const ED25519_OTHER_PUB: &str =
    include_str!("../../tests/fixtures/ed25519_test_signing_other.key.pub");
/// A passphrase-protected Ed25519 key, which the loader must refuse.
pub const ED25519_ENCRYPTED_PEM: &str =
    include_str!("../../tests/fixtures/ed25519_test_encrypted.key");
/// RSA private key in PKCS#1 PEM form: the GitHub App key most tests register.
pub const RSA_TEST_1_PEM: &str = include_str!("../../tests/fixtures/rsa_test_1.pem");
/// The public half of [`RSA_TEST_1_PEM`].
pub const RSA_TEST_1_PUB: &str = include_str!("../../tests/fixtures/rsa_test_1.pub.pem");
/// The public half of a different RSA key, for mismatched-key JWT checks.
pub const RSA_TEST_2_PUB: &str = include_str!("../../tests/fixtures/rsa_test_2.pub.pem");
/// An RSA private key that the signing-key loader must load and then refuse
/// to sign with.
pub const RSA_LOAD_ONLY_PEM: &str = include_str!("../../tests/fixtures/rsa_test_load_only.key");
