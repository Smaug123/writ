//! Unit + property tests for the Nix binary-cache value types and narinfo
//! parsing. Split out of `nix_binary_cache.rs` (an inline `#[cfg(test)]`
//! module) to keep the production file readable; the tests are unchanged.

use super::*;
use proptest::prelude::*;

#[derive(Copy, Clone, Debug)]
enum NarInfoMutation {
    MissingStorePath,
    DuplicateStorePath,
    WrongStoreHash,
    BadStorePathPrefix,
    BadStorePathName,
    MissingUrl,
    DuplicateUrl,
    UnsafeUrl,
    MissingCompression,
    DuplicateCompression,
    EmptyCompression,
    BadCompression,
    MissingNarHash,
    DuplicateNarHash,
    MalformedNarHash,
    EmptyNarHashAlgorithm,
    BadNarHashAlgorithm,
    BadNarHashDigest,
    MissingNarSize,
    DuplicateNarSize,
    EmptyNarSize,
    BadNarSize,
    DuplicateReferences,
    BadReferences,
    MissingSignature,
    BadSignature,
}

const TEST_PUBLIC_KEY: &str = "cache.example:IsGkyTbr2sed7tWowgiPcI0ZHhBAHoGQ7TyYRweyzwE=";
const TEST_SIGNATURE: &str = "cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==";
const TEST_SIGNED_NARINFO: &str = concat!(
    "StorePath: /nix/store/rzv95bakh41zrn5ji23pfc11x5vq2z4d-src\n",
    "URL: nar/05cwbm7srkm5hvm6s7pa8yw2n57vgfrfmsz3p2sy8h9cnki9415f.nar.xz\n",
    "Compression: xz\n",
    "FileHash: sha256:05cwbm7srkm5hvm6s7pa8yw2n57vgfrfmsz3p2sy8h9cnki9415f\n",
    "FileSize: 128\n",
    "NarHash: sha256:0n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny\n",
    "NarSize: 120\n",
    "References: \n",
    "Sig: cache.example:ioaqsTngbhwHmkI+4GKXEkuV0WvrIQ0+SUVlVvIix5A7h31h6oE5hpQbq/rGvH10QLVtYm82sdIM3e2SBGqMAA==\n",
    "CA: fixed:sha256:1ivkzvg86cqy19yf9bg4aaqf6a9prfbjn18jclk6k2w2c9is5kf1\n",
);
const TEST_REFS_PUBLIC_KEY: &str = "cache.refs:BHW8e1tReqeVluuat3LaQIoeVPa7g2+8My8XCqqN1is=";
const TEST_REFS_SIGNED_NARINFO: &str = concat!(
    "StorePath: /nix/store/9z4l1xiz8325yqi8f8q5ls6jv7jzaqam-root.txt\n",
    "URL: nar/1pfjl5iww7b44zgwajhlafpzm51i07f7lklksqj676dk3qjbwgaz.nar.xz\n",
    "Compression: xz\n",
    "FileHash: sha256:1pfjl5iww7b44zgwajhlafpzm51i07f7lklksqj676dk3qjbwgaz\n",
    "FileSize: 208\n",
    "NarHash: sha256:1m7hc9pwbk762qsf5yrv2nadbvr9lhzb76f3qia2a9x0gpxjbvm3\n",
    "NarSize: 216\n",
    "References: sx5305c45zn199v0gv0x7vnh3z9q658x-b.txt z2gxprmwxdfyrb4rka1629bvxxa429ga-a.txt\n",
    "Sig: cache.refs:9Cd6wxkYijT02Ik4HooBeoTA7asg4pv5aa0lV+BfA/XoJs1qycPUmHle3JE5NgEDUD5wuTBST3VcXzgj3NcvAg==\n",
    "CA: text:sha256:1a778zsfa68nz0220y8z93xnw4c1pbfwkk2kbwd2xas0qj3l467v\n",
);

fn valid_store_hash_part() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(NIX_STORE_HASH_ALPHABET.to_vec()),
        NIX_STORE_HASH_LEN..=NIX_STORE_HASH_LEN,
    )
    .prop_map(|bytes| String::from_utf8(bytes).unwrap())
}

fn valid_store_name() -> impl Strategy<Value = String> {
    let first = prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', Just(b'_'),];
    let rest = prop::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'+'),
            Just(b'-'),
            Just(b'.'),
            Just(b'_'),
            Just(b'?'),
            Just(b'='),
        ],
        0..80,
    );
    (first, rest).prop_map(|(first, rest)| {
        let mut bytes = Vec::with_capacity(1 + rest.len());
        bytes.push(first);
        bytes.extend(rest);
        String::from_utf8(bytes).unwrap()
    })
}

fn valid_nar_file_name() -> impl Strategy<Value = String> {
    let first = prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', Just(b'_'),];
    let rest = prop::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'-'),
            Just(b'.'),
            Just(b'_'),
            Just(b'+'),
        ],
        0..80,
    );
    (first, rest).prop_map(|(first, rest)| {
        let mut bytes = Vec::with_capacity(1 + rest.len());
        bytes.push(first);
        bytes.extend(rest);
        if bytes.last() == Some(&b'.') {
            *bytes.last_mut().unwrap() = b'x';
        }
        String::from_utf8(bytes).unwrap()
    })
}

fn valid_nar_hash() -> impl Strategy<Value = String> {
    let digest = prop::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'+'),
            Just(b'/'),
            Just(b'='),
            Just(b'-'),
            Just(b'_'),
        ],
        1..80,
    );
    digest.prop_map(|digest| format!("sha256:{}", String::from_utf8(digest).unwrap()))
}

fn narinfo_non_semantic_field() -> impl Strategy<Value = String> {
    let name = prop_oneof![
        Just("Deriver"),
        Just("FileHash"),
        Just("FileSize"),
        Just("CA"),
    ];
    let value = prop::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b' '),
            Just(b':'),
            Just(b'/'),
            Just(b'.'),
            Just(b'-'),
            Just(b'_'),
            Just(b'='),
        ],
        0..80,
    );
    (name, value)
        .prop_map(|(name, value)| format!("{name}: {}\n", String::from_utf8(value).unwrap()))
}

fn narinfo_mutation() -> impl Strategy<Value = NarInfoMutation> {
    prop_oneof![
        Just(NarInfoMutation::MissingStorePath),
        Just(NarInfoMutation::DuplicateStorePath),
        Just(NarInfoMutation::WrongStoreHash),
        Just(NarInfoMutation::BadStorePathPrefix),
        Just(NarInfoMutation::BadStorePathName),
        Just(NarInfoMutation::MissingUrl),
        Just(NarInfoMutation::DuplicateUrl),
        Just(NarInfoMutation::UnsafeUrl),
        Just(NarInfoMutation::MissingCompression),
        Just(NarInfoMutation::DuplicateCompression),
        Just(NarInfoMutation::EmptyCompression),
        Just(NarInfoMutation::BadCompression),
        Just(NarInfoMutation::MissingNarHash),
        Just(NarInfoMutation::DuplicateNarHash),
        Just(NarInfoMutation::MalformedNarHash),
        Just(NarInfoMutation::EmptyNarHashAlgorithm),
        Just(NarInfoMutation::BadNarHashAlgorithm),
        Just(NarInfoMutation::BadNarHashDigest),
        Just(NarInfoMutation::MissingNarSize),
        Just(NarInfoMutation::DuplicateNarSize),
        Just(NarInfoMutation::EmptyNarSize),
        Just(NarInfoMutation::BadNarSize),
        Just(NarInfoMutation::DuplicateReferences),
        Just(NarInfoMutation::BadReferences),
        Just(NarInfoMutation::MissingSignature),
        Just(NarInfoMutation::BadSignature),
    ]
}

fn different_hash(hash: &str) -> String {
    let mut bytes = hash.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}

fn narinfo_body(hash: &str, name: &str, file: &str, nar_hash: &str) -> String {
    format!(
        "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
    )
}

fn nar_hash_digest(nar_hash: &str) -> &str {
    nar_hash
        .split_once(':')
        .expect("valid_nar_hash always includes algorithm separator")
        .1
}

fn mutated_narinfo_body(
    mutation: NarInfoMutation,
    hash: &str,
    name: &str,
    file: &str,
    nar_hash: &str,
) -> String {
    match mutation {
        NarInfoMutation::MissingStorePath => {
            format!(
                "URL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            )
        }
        NarInfoMutation::DuplicateStorePath => format!(
            "StorePath: /nix/store/{hash}-{name}\nStorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::WrongStoreHash => {
            let wrong = different_hash(hash);
            narinfo_body(&wrong, name, file, nar_hash)
        }
        NarInfoMutation::BadStorePathPrefix => {
            format!(
                "StorePath: /bad/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            )
        }
        NarInfoMutation::BadStorePathName => {
            format!(
                "StorePath: /nix/store/{hash}-{name}:bad\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            )
        }
        NarInfoMutation::MissingUrl => {
            format!(
                "StorePath: /nix/store/{hash}-{name}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            )
        }
        NarInfoMutation::DuplicateUrl => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::UnsafeUrl => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/subdir/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::MissingCompression => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::DuplicateCompression => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::EmptyCompression => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: \nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::BadCompression => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: bzip2\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::MissingNarHash => {
            format!(
                "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            )
        }
        NarInfoMutation::DuplicateNarHash => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::MalformedNarHash => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: sha256:{}:extra\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n",
            nar_hash_digest(nar_hash),
        ),
        NarInfoMutation::EmptyNarHashAlgorithm => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: :{}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n",
            nar_hash_digest(nar_hash),
        ),
        NarInfoMutation::BadNarHashAlgorithm => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: SHA256:{}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n",
            nar_hash_digest(nar_hash),
        ),
        NarInfoMutation::BadNarHashDigest => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}@\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::MissingNarSize => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::DuplicateNarSize => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::EmptyNarSize => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: \nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::BadNarSize => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 0120\nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::DuplicateReferences => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nReferences: \nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::BadReferences => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: bad/reference\nSig: {TEST_SIGNATURE}\n"
        ),
        NarInfoMutation::MissingSignature => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \n"
        ),
        NarInfoMutation::BadSignature => format!(
            "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: bad signature\n"
        ),
    }
}

fn expected_mutation_error(
    mutation: NarInfoMutation,
    hash: &str,
    name: &str,
    file: &str,
    nar_hash: &str,
) -> NixNarInfoError {
    match mutation {
        NarInfoMutation::MissingStorePath => NixNarInfoError::MissingStorePath,
        NarInfoMutation::DuplicateStorePath => NixNarInfoError::DuplicateStorePath,
        NarInfoMutation::WrongStoreHash => NixNarInfoError::StorePathHashMismatch {
            expected: NixStoreHashPart::new(hash).unwrap(),
            actual: NixStoreHashPart::new(different_hash(hash)).unwrap(),
        },
        NarInfoMutation::BadStorePathPrefix => NixNarInfoError::InvalidStorePath {
            raw: format!("/bad/store/{hash}-{name}"),
            source: NixStorePathError::MissingStorePrefix,
        },
        NarInfoMutation::BadStorePathName => NixNarInfoError::InvalidStorePath {
            raw: format!("/nix/store/{hash}-{name}:bad"),
            source: NixStorePathError::InvalidNameByte,
        },
        NarInfoMutation::MissingUrl => NixNarInfoError::MissingUrl,
        NarInfoMutation::DuplicateUrl => NixNarInfoError::DuplicateUrl,
        NarInfoMutation::UnsafeUrl => NixNarInfoError::InvalidNarFile {
            url: format!("nar/subdir/{file}"),
            source: NixCacheNarFileNameError::Slash,
        },
        NarInfoMutation::MissingCompression => NixNarInfoError::MissingCompression,
        NarInfoMutation::DuplicateCompression => NixNarInfoError::DuplicateCompression,
        NarInfoMutation::EmptyCompression => NixNarInfoError::EmptyCompression,
        NarInfoMutation::BadCompression => NixNarInfoError::InvalidCompression {
            raw: "bzip2".into(),
            source: NixNarCompressionError::Unsupported,
        },
        NarInfoMutation::MissingNarHash => NixNarInfoError::MissingNarHash,
        NarInfoMutation::DuplicateNarHash => NixNarInfoError::DuplicateNarHash,
        NarInfoMutation::MalformedNarHash => NixNarInfoError::InvalidNarHash {
            raw: format!("sha256:{}:extra", nar_hash_digest(nar_hash)),
            source: NixNarHashError::TooManySeparators,
        },
        NarInfoMutation::EmptyNarHashAlgorithm => NixNarInfoError::InvalidNarHash {
            raw: format!(":{}", nar_hash_digest(nar_hash)),
            source: NixNarHashError::EmptyAlgorithm,
        },
        NarInfoMutation::BadNarHashAlgorithm => NixNarInfoError::InvalidNarHash {
            raw: format!("SHA256:{}", nar_hash_digest(nar_hash)),
            source: NixNarHashError::InvalidAlgorithmByte,
        },
        NarInfoMutation::BadNarHashDigest => NixNarInfoError::InvalidNarHash {
            raw: format!("{nar_hash}@"),
            source: NixNarHashError::InvalidDigestByte,
        },
        NarInfoMutation::MissingNarSize => NixNarInfoError::MissingNarSize,
        NarInfoMutation::DuplicateNarSize => NixNarInfoError::DuplicateNarSize,
        NarInfoMutation::EmptyNarSize => NixNarInfoError::EmptyNarSize,
        NarInfoMutation::BadNarSize => NixNarInfoError::InvalidNarSize {
            raw: "0120".into(),
            source: NixNarSizeError::LeadingZero,
        },
        NarInfoMutation::DuplicateReferences => NixNarInfoError::DuplicateReferences,
        NarInfoMutation::BadReferences => NixNarInfoError::InvalidReferences {
            raw: "bad/reference".into(),
            source: NixNarReferencesError::InvalidReference {
                raw: "bad/reference".into(),
                source: NixStorePathError::NestedPathSegment,
            },
        },
        NarInfoMutation::MissingSignature => NixNarInfoError::MissingSignature,
        NarInfoMutation::BadSignature => NixNarInfoError::InvalidSignature {
            raw: "bad signature".into(),
            source: NixNarSignatureError::MissingSeparator,
        },
    }
}

fn valid_key_name() -> impl Strategy<Value = String> {
    let first = prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9',];
    let rest = prop::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b'-'),
            Just(b'.'),
            Just(b'_'),
            Just(b'~'),
        ],
        0..32,
    );
    (first, rest).prop_map(|(first, rest)| {
        let mut bytes = Vec::with_capacity(1 + rest.len());
        bytes.push(first);
        bytes.extend(rest);
        String::from_utf8(bytes).unwrap()
    })
}

fn valid_public_key_material() -> impl Strategy<Value = String> {
    prop::collection::vec(
        any::<u8>(),
        NIX_ED25519_PUBLIC_KEY_LEN..=NIX_ED25519_PUBLIC_KEY_LEN,
    )
    .prop_map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn invalid_name_char() -> impl Strategy<Value = char> {
    any::<char>().prop_filter("invalid Nix key name character", |ch| {
        !ch.is_ascii_alphanumeric() && !matches!(*ch, '-' | '.' | '_' | '~' | ':')
    })
}

fn invalid_base64_char() -> impl Strategy<Value = char> {
    prop_oneof![
        Just('-'),
        Just('_'),
        Just('.'),
        Just(' '),
        Just('\n'),
        Just('@'),
    ]
}

proptest! {
    #[test]
    fn valid_narinfo_parse_amid_arbitrary_other_fields(
        hash in valid_store_hash_part(),
        name in valid_store_name(),
        file in valid_nar_file_name(),
        nar_hash in valid_nar_hash(),
        before in prop::collection::vec(narinfo_non_semantic_field(), 0..8),
        after in prop::collection::vec(narinfo_non_semantic_field(), 0..8),
    ) {
        let raw = format!(
            "{}Deriver: /nix/store/00000000000000000000000000000000-proof:drv\nStorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: {nar_hash}\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n{}",
            before.concat(),
            after.concat(),
        );

        let expected_hash = NixStoreHashPart::new(hash.clone()).unwrap();
        let parsed = parse_narinfo_for_store_hash(raw.as_bytes(), &expected_hash).unwrap();

        prop_assert_eq!(parsed.store_path().as_str(), format!("/nix/store/{hash}-{name}"));
        prop_assert_eq!(parsed.store_path().hash().as_str(), hash.as_str());
        prop_assert_eq!(parsed.nar_file().as_str(), file.as_str());
        prop_assert_eq!(parsed.compression(), NixNarCompression::Xz);
        prop_assert_eq!(parsed.nar_hash().as_str(), nar_hash.as_str());
        prop_assert_eq!(parsed.nar_size().get(), 120);
    }

    #[test]
    fn mutated_load_bearing_narinfo_fields_are_rejected(
        hash in valid_store_hash_part(),
        name in valid_store_name(),
        file in valid_nar_file_name(),
        nar_hash in valid_nar_hash(),
        mutation in narinfo_mutation(),
    ) {
        let expected_hash = NixStoreHashPart::new(hash.clone()).unwrap();
        let raw = mutated_narinfo_body(mutation, &hash, &name, &file, &nar_hash);
        let expected = expected_mutation_error(mutation, &hash, &name, &file, &nar_hash);

        prop_assert_eq!(
            parse_narinfo_for_store_hash(raw.as_bytes(), &expected_hash),
            Err(expected),
            "mutation {:?} produced the wrong result for {:?}",
            mutation,
            raw,
        );
    }

    #[test]
    fn narinfo_parser_is_total_for_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_narinfo(&bytes);
    }

    #[test]
    fn generated_valid_trusted_public_keys_parse(
        name in valid_key_name(),
        key in valid_public_key_material(),
    ) {
        let raw = format!("{name}:{key}");
        let parsed = NixTrustedPublicKey::new(raw.clone()).unwrap();
        prop_assert_eq!(parsed.as_str(), raw);
        prop_assert_eq!(parsed.name(), name.as_str());
    }

    #[test]
    fn invalid_name_bytes_are_rejected(
        name in valid_key_name(),
        key in valid_public_key_material(),
        bad in invalid_name_char(),
    ) {
        let raw = format!("{name}{bad}:{key}");
        prop_assert_eq!(
            NixTrustedPublicKey::new(raw),
            Err(NixTrustedPublicKeyError::InvalidNameByte)
        );
    }

    #[test]
    fn invalid_base64_material_bytes_are_rejected(
        name in valid_key_name(),
        key in valid_public_key_material(),
        bad in invalid_base64_char(),
    ) {
        let mut key = key.into_bytes();
        key[0] = bad as u8;
        let key = String::from_utf8(key).unwrap();
        let raw = format!("{name}:{key}");
        prop_assert_eq!(
            NixTrustedPublicKey::new(raw),
            Err(NixTrustedPublicKeyError::InvalidKeyByte)
        );
    }

    #[test]
    fn trusted_public_keys_join_as_nix_conf_value(
        first_name in valid_key_name(),
        first_key in valid_public_key_material(),
        second_key in valid_public_key_material(),
    ) {
        let second_name = format!("{first_name}-other");
        let first = format!("{first_name}:{first_key}");
        let second = format!("{second_name}:{second_key}");
        let keys = NixTrustedPublicKeys::from_strings([first.clone(), second.clone()]).unwrap();
        prop_assert_eq!(keys.nix_conf_value(), format!("{first} {second}"));
    }
}

#[test]
fn nix_base32_sha256_matches_nix_fixture_for_empty_file() {
    let digest = ring::digest::digest(&ring::digest::SHA256, b"");
    let digest: [u8; NIX_SHA256_DIGEST_LEN] = digest.as_ref().try_into().unwrap();

    assert_eq!(
        nix_base32_encode_sha256_digest(&digest),
        "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73",
    );
}

#[test]
fn nar_hash_verifies_sha256_body_and_rejects_mismatch() {
    let hash =
        NixNarHash::new("sha256:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73").unwrap();

    hash.verify_sha256_body(b"").unwrap();
    assert!(matches!(
        hash.verify_sha256_body(b"not empty"),
        Err(NixNarBodyHashError::Mismatch { .. })
    ));
}

#[test]
fn nar_hash_body_verification_rejects_unsupported_shapes() {
    assert_eq!(
        NixNarHash::new("sha1:0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73")
            .unwrap()
            .verify_sha256_body(b""),
        Err(NixNarBodyHashError::UnsupportedAlgorithm {
            algorithm: "sha1".into()
        })
    );
    assert_eq!(
        NixNarHash::new("sha256:0").unwrap().verify_sha256_body(b""),
        Err(NixNarBodyHashError::InvalidDigestLength { actual: 1 })
    );
}

#[test]
fn nix_generated_signed_narinfo_verifies_with_trusted_key() {
    let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let keys = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();

    let parsed =
        parse_signed_narinfo_for_store_hash(TEST_SIGNED_NARINFO.as_bytes(), &expected_hash, &keys)
            .unwrap();

    assert_eq!(parsed.compression(), NixNarCompression::Xz);
    assert_eq!(parsed.nar_size().get(), 120);
    assert_eq!(parsed.references().iter().count(), 0);
    assert_eq!(parsed.signatures()[0].key_name(), "cache.example");
}

#[test]
fn nar_compression_parses_supported_values_and_round_trips() {
    for (raw, parsed) in [
        ("none", NixNarCompression::None),
        ("xz", NixNarCompression::Xz),
        ("zstd", NixNarCompression::Zstd),
    ] {
        assert_eq!(NixNarCompression::new(raw), Ok(parsed));
        assert_eq!(parsed.as_str(), raw);
    }
    // Compression is not part of the signed fingerprint, so switching the
    // upstream to zstd is admitted (and typed as such) exactly like xz.
    assert_eq!(
        NixNarCompression::new("bzip2"),
        Err(NixNarCompressionError::Unsupported),
    );
}

#[test]
fn nix_generated_signed_narinfo_verifies_non_empty_references() {
    let expected_hash = NixStoreHashPart::new("9z4l1xiz8325yqi8f8q5ls6jv7jzaqam").unwrap();
    let keys = NixTrustedPublicKeys::from_strings([TEST_REFS_PUBLIC_KEY]).unwrap();

    let parsed = parse_signed_narinfo_for_store_hash(
        TEST_REFS_SIGNED_NARINFO.as_bytes(),
        &expected_hash,
        &keys,
    )
    .unwrap();

    let references = parsed
        .references()
        .iter()
        .map(NixStorePath::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        references,
        vec![
            "/nix/store/sx5305c45zn199v0gv0x7vnh3z9q658x-b.txt",
            "/nix/store/z2gxprmwxdfyrb4rka1629bvxxa429ga-a.txt",
        ],
    );
    assert_eq!(parsed.nar_size().get(), 216);
    assert_eq!(parsed.compression(), NixNarCompression::Xz);
    assert_eq!(parsed.signatures()[0].key_name(), "cache.refs");
}

#[test]
fn signed_narinfo_rejects_mutated_signed_fields() {
    let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let keys = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
    for mutated in [
        TEST_SIGNED_NARINFO.replace("NarSize: 120\n", "NarSize: 121\n"),
        TEST_SIGNED_NARINFO.replace(
            "NarHash: sha256:0n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny\n",
            "NarHash: sha256:1n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny\n",
        ),
        TEST_SIGNED_NARINFO.replace(
            "References: \n",
            "References: rzv95bakh41zrn5ji23pfc11x5vq2z4d-src\n",
        ),
    ] {
        assert_eq!(
            parse_signed_narinfo_for_store_hash(mutated.as_bytes(), &expected_hash, &keys),
            Err(NixNarInfoError::SignatureMismatch),
            "{mutated:?}",
        );
    }
}

/// A real cache.nixos.org narinfo for a reference-free fixed-output source
/// path. cache.nixos.org omits the `References:` line entirely when a path
/// has no references (it does not emit an empty `References: `), and signs
/// the fingerprint over an empty reference set. The broker must read the
/// absent line as zero references and verify the signature.
///
/// Regression for the nixpkgs refresh that shipped both zstd NARs and
/// reference-less narinfos: the zstd half was fixed in #249, but the
/// missing-`References` half kept surfacing to no-egress guests as a generic
/// 502 "nix cache upstream failed" (audit label
/// "missing upstream narinfo References").
#[test]
fn real_reference_free_cache_narinfo_parses_and_verifies() {
    const CACHE_NIXOS_ORG_KEY: &str =
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
    // Fetched verbatim from
    // https://cache.nixos.org/3lm9ri9lk37f3yhmnybb31ikaj6imivh.narinfo —
    // note there is no `References:` line at all.
    const NARINFO: &str = concat!(
        "StorePath: /nix/store/3lm9ri9lk37f3yhmnybb31ikaj6imivh-cargo-src-proc-macro2-1.0.106\n",
        "URL: nar/0rcd3qyis3ykddalcdn1z5z6l8iq8cx68f7bff9jpgdjifqfd7zi.nar.zst\n",
        "Compression: zstd\n",
        "FileHash: sha256:0y3f4mr1dli672alabhywgvsfxw2gzs0sczacdkgni90hykh08bs\n",
        "FileSize: 59889\n",
        "NarHash: sha256:0rcd3qyis3ykddalcdn1z5z6l8iq8cx68f7bff9jpgdjifqfd7zi\n",
        "NarSize: 59880\n",
        "Deriver: 8mj278wp2b0asr28gzw8gjfp66nzi867-cargo-src-proc-macro2-1.0.106.drv\n",
        "Sig: cache.nixos.org-1:PwivEPG8TMkGlbzyfBS6CSCiGyOMVm/JTV+yqXbP+dxT4ZHsF0c2O/GNw3ipP9z70qBe7SaIdBwWWOuXrfwwCQ==\n",
        "CA: fixed:sha256:0d09nczyaj67x4ihqr5p7gxbkz38gxhk4asc0k8q23g9n85hzl4g\n",
    );

    let expected_hash = NixStoreHashPart::new("3lm9ri9lk37f3yhmnybb31ikaj6imivh").unwrap();
    let keys = NixTrustedPublicKeys::from_strings([CACHE_NIXOS_ORG_KEY]).unwrap();

    let narinfo = parse_signed_narinfo_for_store_hash(NARINFO.as_bytes(), &expected_hash, &keys)
        .expect("reference-free signed narinfo must parse and verify");
    assert_eq!(narinfo.references().iter().count(), 0);
    assert_eq!(narinfo.compression(), NixNarCompression::Zstd);
}

/// An absent `References:` line is indistinguishable from an explicit empty
/// one: both mean zero references, feed the same signed fingerprint, and so
/// verify against the same signature. Uses the locally-signed test narinfo
/// (whose fingerprint is over empty references) with its `References:` line
/// deleted, so signature parity is checked, not just parseability.
#[test]
fn absent_references_line_matches_explicit_empty() {
    let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let keys = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
    let without_references = TEST_SIGNED_NARINFO.replace("References: \n", "");
    assert!(
        !without_references.contains("References"),
        "the test narinfo must have no References line for this case",
    );

    let with_empty =
        parse_signed_narinfo_for_store_hash(TEST_SIGNED_NARINFO.as_bytes(), &expected_hash, &keys)
            .expect("explicit empty References parses and verifies");
    let without =
        parse_signed_narinfo_for_store_hash(without_references.as_bytes(), &expected_hash, &keys)
            .expect("absent References line parses and verifies");

    assert_eq!(with_empty.references().iter().count(), 0);
    assert_eq!(without.references().iter().count(), 0);
    assert_eq!(
        with_empty.signature_fingerprint(),
        without.signature_fingerprint()
    );
}

#[test]
fn signed_narinfo_requires_a_configured_trusted_key() {
    let expected_hash = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let keys = NixTrustedPublicKeys::empty();

    assert_eq!(
        parse_signed_narinfo_for_store_hash(TEST_SIGNED_NARINFO.as_bytes(), &expected_hash, &keys),
        Err(NixNarInfoError::UntrustedSignatureKey),
    );
}

#[test]
fn malformed_narinfo_urls_are_rejected() {
    let prefix = "StorePath: /nix/store/00000000000000000000000000000000-proof\n";
    let suffix = format!(
        "Compression: xz\nNarHash: sha256:0\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
    );
    let cases = vec![
        (
            format!("URL: nar/proof.nar\n{suffix}"),
            NixNarInfoError::MissingStorePath,
        ),
        (
            format!("StorePath: \nURL: nar/proof.nar\n{suffix}"),
            NixNarInfoError::EmptyStorePath,
        ),
        (
            format!("StorePath: /nix/store/x\nURL: nar/proof.nar\n{suffix}"),
            NixNarInfoError::InvalidStorePath {
                raw: "/nix/store/x".into(),
                source: NixStorePathError::MissingNameSeparator,
            },
        ),
        (
            format!(
                "{prefix}StorePath: /nix/store/00000000000000000000000000000000-proof\nURL: nar/proof.nar\n{suffix}"
            ),
            NixNarInfoError::DuplicateStorePath,
        ),
        (format!("{prefix}{suffix}"), NixNarInfoError::MissingUrl),
        (
            format!("{prefix}URL: \n{suffix}"),
            NixNarInfoError::EmptyUrl,
        ),
        (
            "URL: nar/proof.nar\nURL: nar/other.nar\n".to_string(),
            NixNarInfoError::DuplicateUrl,
        ),
        (
            format!(
                "{prefix}URL: nar/proof.nar\nCompression: xz\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NixNarInfoError::MissingNarHash,
        ),
        (
            format!(
                "{prefix}URL: nar/proof.nar\nCompression: xz\nNarHash: \nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NixNarInfoError::EmptyNarHash,
        ),
        (
            format!(
                "{prefix}URL: nar/proof.nar\nCompression: xz\nNarHash: sha256:0\nNarHash: sha256:0\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NixNarInfoError::DuplicateNarHash,
        ),
        (
            format!(
                "{prefix}URL: nar/proof.nar\nCompression: xz\nNarHash: sha256:0:extra\nNarSize: 120\nReferences: \nSig: {TEST_SIGNATURE}\n"
            ),
            NixNarInfoError::InvalidNarHash {
                raw: "sha256:0:extra".into(),
                source: NixNarHashError::TooManySeparators,
            },
        ),
        (
            format!("{prefix}URL: https://cache.example/nar/proof.nar\n{suffix}"),
            NixNarInfoError::UnsupportedUrl("https://cache.example/nar/proof.nar".into()),
        ),
        (
            format!("{prefix}URL: ../proof.nar\n{suffix}"),
            NixNarInfoError::UnsupportedUrl("../proof.nar".into()),
        ),
        (
            format!("{prefix}URL: nar/subdir/proof.nar\n{suffix}"),
            NixNarInfoError::InvalidNarFile {
                url: "nar/subdir/proof.nar".into(),
                source: NixCacheNarFileNameError::Slash,
            },
        ),
        (
            format!("{prefix}URL: nar/proof.nar?download=1\n{suffix}"),
            NixNarInfoError::InvalidNarFile {
                url: "nar/proof.nar?download=1".into(),
                source: NixCacheNarFileNameError::InvalidByte,
            },
        ),
        (
            format!("{prefix}URL: nar/.proof.nar\n{suffix}"),
            NixNarInfoError::InvalidNarFile {
                url: "nar/.proof.nar".into(),
                source: NixCacheNarFileNameError::DotBoundary,
            },
        ),
        (
            format!("{prefix}URL: nar/proof.nar.\n{suffix}"),
            NixNarInfoError::InvalidNarFile {
                url: "nar/proof.nar.".into(),
                source: NixCacheNarFileNameError::DotBoundary,
            },
        ),
        (
            format!("{prefix}URL: /nar/proof.nar\n{suffix}"),
            NixNarInfoError::UnsupportedUrl("/nar/proof.nar".into()),
        ),
    ];

    for (raw, expected) in cases {
        assert_eq!(parse_narinfo(raw.as_bytes()), Err(expected), "{raw:?}");
    }
}

#[test]
fn malformed_trusted_public_keys_are_rejected() {
    let cases = [
        ("", NixTrustedPublicKeyError::Empty),
        ("cache-key", NixTrustedPublicKeyError::MissingSeparator),
        (":QUJDRA==", NixTrustedPublicKeyError::EmptyName),
        ("cache.example-1:", NixTrustedPublicKeyError::EmptyKey),
        (
            "cache.example-1:QUJDRA==:extra",
            NixTrustedPublicKeyError::TooManySeparators,
        ),
        (
            "cache example-1:QUJDRA==",
            NixTrustedPublicKeyError::InvalidNameByte,
        ),
        (
            "cache.example-1:QUJDRA==\n",
            NixTrustedPublicKeyError::InvalidBase64Padding,
        ),
        (
            "cache.example-1:QUJDRA===",
            NixTrustedPublicKeyError::InvalidBase64Padding,
        ),
        (
            "cache.example-1:abcde",
            NixTrustedPublicKeyError::InvalidBase64Length,
        ),
        (
            "cache.example-1:QUJDRA==",
            NixTrustedPublicKeyError::InvalidPublicKeyLength,
        ),
    ];

    for (raw, expected) in cases {
        assert_eq!(NixTrustedPublicKey::new(raw), Err(expected), "{raw:?}");
    }
}

#[test]
fn trusted_public_keys_error_reports_index_and_raw_value() {
    let valid_material = TEST_PUBLIC_KEY.split_once(':').unwrap().1;
    let bad_key = format!("bad key:{valid_material}");
    let err = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY, bad_key.as_str()]).unwrap_err();

    assert_eq!(err.index(), 1);
    assert_eq!(err.raw(), bad_key);
    assert_eq!(err.source(), &NixTrustedPublicKeyError::InvalidNameByte);
}

#[test]
fn trusted_public_keys_reject_duplicate_names() {
    let first = TEST_PUBLIC_KEY;
    let second = format!(
        "cache.example:{}",
        TEST_REFS_PUBLIC_KEY.split_once(':').unwrap().1
    );

    let err = NixTrustedPublicKeys::from_strings([first, second.as_str()]).unwrap_err();

    assert_eq!(err.index(), 1);
    assert_eq!(err.raw(), second);
    assert_eq!(err.source(), &NixTrustedPublicKeyError::DuplicateName);
}

// --- content-addressed (unsigned) narinfo admission ---
//
// Exactly what `nix flake archive --to file://<cache>` writes: an unsigned
// narinfo carrying `CA: fixed:r:sha256:<digest>` where `<digest>` equals the
// NarHash digest. The store hash and digests below are taken verbatim from a
// real archive of `github:numtide/flake-utils`.
const ARCHIVE_CA_STORE_HASH: &str = "yj1wxm9hh8610iyzqnz75kvs6xl8j3my";
const ARCHIVE_CA_NAR_DIGEST: &str = "1bzg89hgcr2gvza35vqi4n1jbb2gz1yg4b8p7gry4ihsj2mnnbap";
const ARCHIVE_CA_NARINFO: &str = concat!(
    "StorePath: /nix/store/yj1wxm9hh8610iyzqnz75kvs6xl8j3my-source\n",
    "URL: nar/096mx83hxig0azq3zk8q1ali20sd85d2xirzfylnngfn8gp3akmv.nar.xz\n",
    "Compression: xz\n",
    "FileHash: sha256:096mx83hxig0azq3zk8q1ali20sd85d2xirzfylnngfn8gp3akmv\n",
    "FileSize: 1100\n",
    "NarHash: sha256:1bzg89hgcr2gvza35vqi4n1jbb2gz1yg4b8p7gry4ihsj2mnnbap\n",
    "NarSize: 2440\n",
    "References: \n",
    "CA: fixed:r:sha256:1bzg89hgcr2gvza35vqi4n1jbb2gz1yg4b8p7gry4ihsj2mnnbap\n",
);

fn nar_digest_for_body(body: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    let digest: [u8; NIX_SHA256_DIGEST_LEN] = digest.as_ref().try_into().unwrap();
    nix_base32_encode_sha256_digest(&digest)
}

fn unsigned_ca_narinfo(
    hash: &str,
    name: &str,
    file: &str,
    nar_digest: &str,
    nar_size: u64,
    ca: &str,
) -> String {
    format!(
        "StorePath: /nix/store/{hash}-{name}\nURL: nar/{file}\nCompression: xz\nNarHash: sha256:{nar_digest}\nNarSize: {nar_size}\nReferences: \nCA: {ca}\n"
    )
}

#[test]
fn archive_style_unsigned_ca_narinfo_is_admitted() {
    let expected = NixStoreHashPart::new(ARCHIVE_CA_STORE_HASH).unwrap();
    let parsed =
        parse_content_addressed_narinfo_for_store_hash(ARCHIVE_CA_NARINFO.as_bytes(), &expected)
            .unwrap();

    assert_eq!(parsed.store_path().hash().as_str(), ARCHIVE_CA_STORE_HASH);
    assert_eq!(
        parsed.nar_file().as_str(),
        "096mx83hxig0azq3zk8q1ali20sd85d2xirzfylnngfn8gp3akmv.nar.xz"
    );
    assert_eq!(parsed.compression(), NixNarCompression::Xz);
    assert_eq!(parsed.nar_hash().digest(), ARCHIVE_CA_NAR_DIGEST);
    assert_eq!(parsed.nar_size().get(), 2440);
    // Crucially admitted with no signature at all.
    assert!(parsed.signatures().is_empty());
}

#[test]
fn content_addressed_narinfo_requires_a_ca_field() {
    // The archive narinfo with its CA line removed: a well-formed but
    // unsigned, non-self-certifying narinfo must be refused.
    let without_ca = ARCHIVE_CA_NARINFO
        .lines()
        .filter(|line| !line.starts_with("CA:"))
        .collect::<Vec<_>>()
        .join("\n");
    let expected = NixStoreHashPart::new(ARCHIVE_CA_STORE_HASH).unwrap();

    assert_eq!(
        parse_content_addressed_narinfo_for_store_hash(without_ca.as_bytes(), &expected),
        Err(NixContentAddressedNarInfoError::MissingContentAddress),
    );
}

#[test]
fn content_addressed_narinfo_rejects_non_self_certifying_ca() {
    let hash = "00000000000000000000000000000000";
    let expected = NixStoreHashPart::new(hash).unwrap();
    let digest = ARCHIVE_CA_NAR_DIGEST;
    let other_digest = different_hash(digest);
    for ca in [
        // text-hashed, not recursive NAR.
        format!("text:sha256:{digest}"),
        // flat (non-recursive) fixed-output: hash is over the file, not the NAR.
        format!("fixed:sha256:{digest}"),
        // recursive SHA-256, but the digest is not this path's NarHash.
        format!("fixed:r:sha256:{other_digest}"),
        // wrong algorithm.
        format!("fixed:r:sha512:{digest}"),
    ] {
        let raw = unsigned_ca_narinfo(hash, "source", "input.nar.xz", digest, 2440, &ca);
        assert_eq!(
            parse_content_addressed_narinfo_for_store_hash(raw.as_bytes(), &expected),
            Err(NixContentAddressedNarInfoError::NotSelfCertifying {
                content_address: ca.clone(),
                nar_hash: format!("sha256:{digest}"),
            }),
            "CA {ca:?} should not self-certify",
        );
    }
}

#[test]
fn content_addressed_narinfo_rejects_store_hash_mismatch() {
    let store_hash = "00000000000000000000000000000000";
    let requested = "11111111111111111111111111111111";
    let digest = ARCHIVE_CA_NAR_DIGEST;
    let raw = unsigned_ca_narinfo(
        store_hash,
        "source",
        "input.nar.xz",
        digest,
        2440,
        &format!("fixed:r:sha256:{digest}"),
    );
    let expected = NixStoreHashPart::new(requested).unwrap();

    assert_eq!(
        parse_content_addressed_narinfo_for_store_hash(raw.as_bytes(), &expected),
        Err(NixContentAddressedNarInfoError::NarInfo(
            NixNarInfoError::StorePathHashMismatch {
                expected: NixStoreHashPart::new(requested).unwrap(),
                actual: NixStoreHashPart::new(store_hash).unwrap(),
            }
        )),
    );
}

#[test]
fn content_addressed_narinfo_still_requires_well_formed_fields() {
    // A self-certifying CA does not excuse a malformed narinfo.
    let digest = ARCHIVE_CA_NAR_DIGEST;
    let raw = format!(
        "StorePath: /nix/store/00000000000000000000000000000000-source\nCompression: xz\nNarHash: sha256:{digest}\nNarSize: 2440\nReferences: \nCA: fixed:r:sha256:{digest}\n"
    );
    let expected = NixStoreHashPart::new("00000000000000000000000000000000").unwrap();

    assert_eq!(
        parse_content_addressed_narinfo_for_store_hash(raw.as_bytes(), &expected),
        Err(NixContentAddressedNarInfoError::NarInfo(
            NixNarInfoError::MissingUrl
        )),
    );
}

#[test]
fn signed_narinfo_with_flat_ca_is_not_admitted_unsigned() {
    // The trusted-key signed narinfo from the signed-path tests carries a
    // *flat* `fixed:sha256:` CA (hash over the file, not the NAR), so the
    // content-addressed path refuses it: a signature is not a content
    // address, and a flat CA is not verified by NarHash. It would still be
    // admitted by the *signed* path.
    let expected = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    assert_eq!(
        parse_content_addressed_narinfo_for_store_hash(TEST_SIGNED_NARINFO.as_bytes(), &expected),
        Err(NixContentAddressedNarInfoError::NotSelfCertifying {
            content_address: "fixed:sha256:1ivkzvg86cqy19yf9bg4aaqf6a9prfbjn18jclk6k2w2c9is5kf1"
                .to_owned(),
            nar_hash: "sha256:0n62ny3wh4ayp887m60r6ja1p7hrdqnlaq2avb1177zc5gmm6nny".to_owned(),
        }),
    );
}

#[test]
fn fixed_output_store_hash_matches_nix_for_real_archive_paths() {
    // (CA digest, name) -> store hash, taken verbatim from a real
    // `nix flake archive` of `github:numtide/flake-utils`. This pins the
    // derivation against Nix itself, so the self-certification cannot drift.
    for (digest, name, expected) in [
        (
            "1cii9id0k1vsa3r53k54bndyl6kxzgm1nsgj7gncgbp3j61qahlp",
            "source",
            "01x5k4nlxcpyd85nnr0b9gm89rm8ff4x",
        ),
        (
            "00r0rqlxr7f3rmc5rn4055x9lv6jzal6d9gh39mny2byaiczzlld",
            "source",
            "h5jznf8hfa1690xlk7qmf34iia8mh2hh",
        ),
        (ARCHIVE_CA_NAR_DIGEST, "source", ARCHIVE_CA_STORE_HASH),
    ] {
        assert_eq!(
            fixed_output_recursive_sha256_store_hash(digest, name).as_deref(),
            Some(expected),
            "derivation mismatch for {name}",
        );
    }
}

#[test]
fn content_addressed_narinfo_rejects_store_hash_not_derived_from_ca() {
    // A self-certifying CA (CA == NarHash) but a StorePath hash that is not
    // the fixed-output path of that content: identity does not match content.
    let digest = ARCHIVE_CA_NAR_DIGEST;
    let wrong_hash = "00000000000000000000000000000000";
    let raw = unsigned_ca_narinfo(
        wrong_hash,
        "source",
        "input.nar.xz",
        digest,
        2440,
        &format!("fixed:r:sha256:{digest}"),
    );
    let expected = NixStoreHashPart::new(wrong_hash).unwrap();
    assert!(
        matches!(
            parse_content_addressed_narinfo_for_store_hash(raw.as_bytes(), &expected),
            Err(NixContentAddressedNarInfoError::StorePathNotContentDerived { .. })
        ),
        "a non-derived store hash must be refused",
    );
}

#[test]
fn content_addressed_narinfo_rejects_wrong_store_name_for_ca() {
    // The real archive narinfo, but the store name changed: the derived hash
    // depends on the name, so identity no longer matches.
    let raw = ARCHIVE_CA_NARINFO.replace("-source\n", "-renamed\n");
    let expected = NixStoreHashPart::new(ARCHIVE_CA_STORE_HASH).unwrap();
    assert!(
        matches!(
            parse_content_addressed_narinfo_for_store_hash(raw.as_bytes(), &expected),
            Err(NixContentAddressedNarInfoError::StorePathNotContentDerived { .. })
        ),
        "a mismatched store name must be refused",
    );
}

#[test]
fn content_addressed_narinfo_with_references_is_refused() {
    // A correctly-derived, self-certifying reference-free narinfo is admitted;
    // adding a reference makes it a referenced fixed-output, which the broker
    // refuses (only the reference-free derivation is verified).
    let body = b"a body with references added later";
    let nar_digest = nar_digest_for_body(body);
    let store_hash = fixed_output_recursive_sha256_store_hash(&nar_digest, "source").unwrap();
    let expected = NixStoreHashPart::new(store_hash.clone()).unwrap();
    let with_reference = format!(
        "StorePath: /nix/store/{store_hash}-source\nURL: nar/input.nar.xz\nCompression: xz\nNarHash: sha256:{nar_digest}\nNarSize: {}\nReferences: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dep\nCA: fixed:r:sha256:{nar_digest}\n",
        body.len(),
    );
    assert!(
        matches!(
            parse_content_addressed_narinfo_for_store_hash(with_reference.as_bytes(), &expected),
            Err(NixContentAddressedNarInfoError::StorePathNotContentDerived { .. })
        ),
        "a referenced CA path must be refused",
    );

    // Sanity: the same entry without the reference is admitted.
    let without_reference = format!(
        "StorePath: /nix/store/{store_hash}-source\nURL: nar/input.nar.xz\nCompression: xz\nNarHash: sha256:{nar_digest}\nNarSize: {}\nReferences: \nCA: fixed:r:sha256:{nar_digest}\n",
        body.len(),
    );
    assert!(
        parse_content_addressed_narinfo_for_store_hash(without_reference.as_bytes(), &expected)
            .is_ok(),
        "the reference-free entry should be admitted",
    );
}

/// Drop the `CA:` line from a narinfo. The narinfo signature fingerprint is
/// `1;StorePath;NarHash;NarSize;References` — it does not cover `CA` — so a
/// signed narinfo stays validly signed after its CA is removed, yielding a
/// genuinely input-addressed (no-CA) signed narinfo like a devShell output.
fn strip_ca_line(narinfo: &str) -> String {
    narinfo
        .lines()
        .filter(|line| !line.starts_with("CA:"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn local_admissible_admits_self_certifying_ca_with_no_trusted_keys() {
    // The content-addressed path needs no key: a flake-archive narinfo is
    // admitted even when the broker trusts nothing.
    let expected = NixStoreHashPart::new(ARCHIVE_CA_STORE_HASH).unwrap();
    let parsed = parse_local_admissible_narinfo_for_store_hash(
        ARCHIVE_CA_NARINFO.as_bytes(),
        &expected,
        &NixTrustedPublicKeys::empty(),
    )
    .unwrap();
    assert_eq!(parsed.store_path().hash().as_str(), ARCHIVE_CA_STORE_HASH);
    assert!(parsed.signatures().is_empty());
}

#[test]
fn local_admissible_admits_trusted_signed_input_addressed() {
    // A genuinely input-addressed path: TEST_SIGNED_NARINFO with its CA line
    // removed. Admitted via the signature because its key is trusted — this
    // is the pre-warmed devShell-output case PW1 enables.
    let raw = strip_ca_line(TEST_SIGNED_NARINFO);
    let expected = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let trusted = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
    let parsed =
        parse_local_admissible_narinfo_for_store_hash(raw.as_bytes(), &expected, &trusted).unwrap();
    assert_eq!(parsed.signatures().len(), 1);
}

#[test]
fn local_admissible_admits_trusted_signed_with_non_self_certifying_ca() {
    // TEST_SIGNED_NARINFO carries a *flat* `fixed:sha256:` CA (not
    // self-certifying), so the content-addressed path refuses it; the
    // signature path admits it when the key is trusted.
    let expected = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    let trusted = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
    assert!(
        parse_local_admissible_narinfo_for_store_hash(
            TEST_SIGNED_NARINFO.as_bytes(),
            &expected,
            &trusted,
        )
        .is_ok(),
    );
}

#[test]
fn local_admissible_refuses_signed_path_with_untrusted_key() {
    // Same input-addressed signed path, but the broker trusts no key: refused.
    let raw = strip_ca_line(TEST_SIGNED_NARINFO);
    let expected = NixStoreHashPart::new("rzv95bakh41zrn5ji23pfc11x5vq2z4d").unwrap();
    assert_eq!(
        parse_local_admissible_narinfo_for_store_hash(
            raw.as_bytes(),
            &expected,
            &NixTrustedPublicKeys::empty(),
        ),
        Err(NixLocalNarInfoError::UntrustedOrUnsigned(
            NixNarInfoError::UntrustedSignatureKey
        )),
    );
}

#[test]
fn local_admissible_refuses_unsigned_non_self_certifying() {
    // No CA and no Sig: admissible by neither path, even with a trusted key
    // configured.
    let hash = "00000000000000000000000000000000";
    let expected = NixStoreHashPart::new(hash).unwrap();
    let nar_digest = nar_digest_for_body(b"unsigned input-addressed");
    let raw = format!(
        "StorePath: /nix/store/{hash}-out\nURL: nar/x.nar.xz\nCompression: xz\nNarHash: sha256:{nar_digest}\nNarSize: 24\nReferences: \n"
    );
    let trusted = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
    assert_eq!(
        parse_local_admissible_narinfo_for_store_hash(raw.as_bytes(), &expected, &trusted),
        Err(NixLocalNarInfoError::UntrustedOrUnsigned(
            NixNarInfoError::MissingSignature
        )),
    );
}

#[test]
fn local_admissible_propagates_malformation_terminally() {
    let expected = NixStoreHashPart::new("00000000000000000000000000000000").unwrap();
    let trusted = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
    // A signed narinfo for a *different* store hash than requested: a
    // mislabelled file is terminal — never rescued by its (valid) signature.
    let wrong_hash = strip_ca_line(TEST_SIGNED_NARINFO);
    assert!(matches!(
        parse_local_admissible_narinfo_for_store_hash(wrong_hash.as_bytes(), &expected, &trusted),
        Err(NixLocalNarInfoError::Malformed(
            NixNarInfoError::StorePathHashMismatch { .. }
        )),
    ));
    // A missing required field is terminal regardless of trust.
    let digest = ARCHIVE_CA_NAR_DIGEST;
    let no_url = format!(
        "StorePath: /nix/store/00000000000000000000000000000000-out\nCompression: xz\nNarHash: sha256:{digest}\nNarSize: 2440\nReferences: \n"
    );
    assert_eq!(
        parse_local_admissible_narinfo_for_store_hash(no_url.as_bytes(), &expected, &trusted),
        Err(NixLocalNarInfoError::Malformed(NixNarInfoError::MissingUrl)),
    );
}

proptest! {
    /// The admission oracle: an archive-style narinfo is admitted as
    /// content-addressed *iff* its recursive-SHA256 CA digest equals the
    /// actual SHA-256 of the NAR body — and when admitted, that NarHash
    /// really verifies the body. Tying admission to a freshly-hashed body
    /// (rather than a hand-written digest) catches any drift between the CA
    /// check and NAR verification.
    #[test]
    fn recursive_sha256_ca_admits_iff_digest_matches_nar_hash(
        name in valid_store_name(),
        file in valid_nar_file_name(),
        body in prop::collection::vec(any::<u8>(), 0..256),
        tamper in any::<bool>(),
    ) {
        let nar_digest = nar_digest_for_body(&body);
        // The store hash is the Nix fixed-output path of this content + name,
        // so the generated narinfo is exactly what `nix flake archive` writes.
        let store_hash =
            fixed_output_recursive_sha256_store_hash(&nar_digest, &name).unwrap();
        let ca_digest = if tamper { different_hash(&nar_digest) } else { nar_digest.clone() };
        let raw = unsigned_ca_narinfo(
            &store_hash,
            &name,
            &file,
            &nar_digest,
            body.len() as u64,
            &format!("fixed:r:sha256:{ca_digest}"),
        );
        let expected = NixStoreHashPart::new(store_hash).unwrap();
        let result = parse_content_addressed_narinfo_for_store_hash(raw.as_bytes(), &expected);
        if tamper {
            let rejected = matches!(
                result,
                Err(NixContentAddressedNarInfoError::NotSelfCertifying { .. })
            );
            prop_assert!(rejected, "tampered CA digest should be rejected: {result:?}");
        } else {
            let parsed = result.unwrap();
            prop_assert_eq!(parsed.nar_hash().digest(), nar_digest.as_str());
            prop_assert!(parsed.nar_hash().verify_sha256_body(&body).is_ok());
        }
    }

    #[test]
    fn nix_base32_sha256_round_trips(bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
        let digest: [u8; NIX_SHA256_DIGEST_LEN] = bytes.try_into().unwrap();
        let encoded = nix_base32_encode_sha256_digest(&digest);
        prop_assert_eq!(nix_base32_decode_sha256(&encoded), Some(digest));
    }

    #[test]
    fn content_addressed_parser_is_total_for_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        hash in valid_store_hash_part(),
    ) {
        let expected = NixStoreHashPart::new(hash).unwrap();
        let _ = parse_content_addressed_narinfo_for_store_hash(&bytes, &expected);
    }

    /// The local-admission parser never panics on arbitrary bytes / keys,
    /// and — crucially — admitting it never *weakens* the content-addressed
    /// parser: whatever the CA parser admits, the local parser admits too
    /// (the signature path only ever adds, never removes, admissions).
    #[test]
    fn local_admissible_parser_is_total_and_a_superset_of_ca(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        hash in valid_store_hash_part(),
    ) {
        let expected = NixStoreHashPart::new(hash).unwrap();
        let trusted = NixTrustedPublicKeys::from_strings([TEST_PUBLIC_KEY]).unwrap();
        let local = parse_local_admissible_narinfo_for_store_hash(&bytes, &expected, &trusted);
        if parse_content_addressed_narinfo_for_store_hash(&bytes, &expected).is_ok() {
            prop_assert!(local.is_ok(), "CA-admitted narinfo must stay admitted: {local:?}");
        }
    }
}
