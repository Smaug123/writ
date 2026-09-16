#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/create-writd-signing-identity.sh

Create a persistent self-signed code-signing identity for writd.

Why: `writd` binds the broker/UI TCP listeners, and the macOS Application
Firewall filters incoming connections per binary, keyed on the binary's path
and its code-signing designated requirement. An ad-hoc (`codesign --sign -`)
binary's requirement is its cdhash, which changes on every rebuild, so the
firewall re-blocks each fresh build. Signing writd with a stable identity gives
it a stable designated requirement (identifier + this certificate), so one
firewall allow (scripts/allow-writd-firewall.sh) sticks across rebuilds.

This adds ONE code-signing certificate + private key to a keychain. It needs no
sudo. It does NOT get the firewall's auto-allow (that needs an Apple-anchored
Developer ID; see the plan's Tier A) — it makes the manual allow durable.

Environment overrides:
  WRIT_SIGN_IDENTITY_CN        certificate common name (default: "org.writ.writd signing")
  WRIT_SIGN_KEYCHAIN           keychain to import into (default: the login keychain)
  WRIT_SIGN_KEYCHAIN_PASSWORD  if set, authorises codesign to use the key without
                               an interactive Keychain prompt (via
                               `security set-key-partition-list`); otherwise the
                               first codesign run may prompt once ("Always Allow")

Re-running replaces the identity with a fresh certificate; re-run
scripts/install-macos.sh and scripts/allow-writd-firewall.sh afterwards.

See docs/plans/2026-09-16-macos-firewall-stable-identity.md (Stage 2).
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

CN="${WRIT_SIGN_IDENTITY_CN:-org.writ.writd signing}"
KEYCHAIN="${WRIT_SIGN_KEYCHAIN:-$(security default-keychain | tr -d ' "')}"

command -v openssl >/dev/null 2>&1 || { echo "error: openssl is required" >&2; exit 1; }
command -v security >/dev/null 2>&1 || { echo "error: this script is macOS-only (needs security)" >&2; exit 1; }

workdir="$(mktemp -d "${TMPDIR:-/tmp}/writ-signing.XXXXXX")"
trap 'rm -rf "$workdir"' EXIT

# A self-signed leaf with the codeSigning extended key usage. basicConstraints
# CA:false keeps it a leaf; digitalSignature + codeSigning is the minimum a
# code-signing identity needs.
cat > "$workdir/ext.cnf" <<EXT
[ req ]
distinguished_name = dn
x509_extensions    = v3
prompt             = no
[ dn ]
CN = ${CN}
[ v3 ]
basicConstraints   = critical,CA:false
keyUsage           = critical,digitalSignature
extendedKeyUsage   = critical,codeSigning
EXT

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$workdir/key.pem" -out "$workdir/cert.pem" \
  -days 3650 -config "$workdir/ext.cnf" >/dev/null 2>&1

# security import wants a PKCS#12 bundle for a cert+key pair.
p12_pass="$(openssl rand -hex 16)"
openssl pkcs12 -export -inkey "$workdir/key.pem" -in "$workdir/cert.pem" \
  -name "$CN" -out "$workdir/identity.p12" -passout "pass:${p12_pass}" >/dev/null 2>&1

# -T /usr/bin/codesign lets codesign use the key; some macOS versions still
# gate the private key behind a partition list, handled below when a keychain
# password is provided.
security import "$workdir/identity.p12" -k "$KEYCHAIN" -P "$p12_pass" \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null

if [[ -n "${WRIT_SIGN_KEYCHAIN_PASSWORD:-}" ]]; then
  # Authorise Apple's signing tools to read the key non-interactively.
  security set-key-partition-list -S apple-tool:,apple: \
    -k "$WRIT_SIGN_KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null 2>&1 || true
fi

echo "imported code-signing identity into ${KEYCHAIN}:"
# No -v: a self-signed identity is usable for signing but is not "valid"
# (untrusted), so the valid-only listing would hide it.
security find-identity -p codesigning "$KEYCHAIN" | grep -F "$CN" || {
  echo "error: identity '${CN}' not found after import" >&2
  exit 1
}
echo
echo "next:"
echo "  scripts/install-macos.sh          # installs writd, signs it with this identity"
echo "  scripts/allow-writd-firewall.sh   # one-time firewall allow (needs sudo)"
