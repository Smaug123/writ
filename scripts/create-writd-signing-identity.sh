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

The first time codesign uses the key (scripts/install-macos.sh) macOS asks you
to authorise it; click "Always Allow" and it will not ask again. Signing does
not need the key to be trusted, so no trust dialog is involved.

Environment overrides:
  WRIT_SIGN_IDENTITY_CN  certificate common name (default: "org.writ.writd signing")
  WRIT_SIGN_KEYCHAIN     keychain to import into (default: the login keychain)

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
# `security default-keychain` prints the path indented and double-quoted; strip
# only the surrounding indentation and quotes, never spaces inside the path.
KEYCHAIN="${WRIT_SIGN_KEYCHAIN:-$(security default-keychain | sed -E 's/^[[:space:]]*"?//; s/"?[[:space:]]*$//')}"

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

# Re-running must replace, not accumulate: `security import` does not remove a
# previous cert+key with the same name, and two identities sharing a common
# name make `codesign --sign "$CN"` ambiguous (it refuses). Delete any prior
# writd signing identity in this keychain first.
while security find-identity -p codesigning "$KEYCHAIN" | grep -Fq "$CN"; do
  security delete-identity -c "$CN" "$KEYCHAIN" >/dev/null 2>&1 || break
done

# -T /usr/bin/codesign adds codesign to the key's access-control list, so the
# first signing prompts once for "Always Allow" rather than being denied. We do
# NOT touch the keychain's partition list: an unscoped `set-key-partition-list`
# rewrites every key in a shared login keychain and can strip other apps'
# access to their own keys, and a reliably-scoped form is not available. A
# one-time interactive "Always Allow" is the safe path here; automated/CI
# signing should use a dedicated keychain or an Apple Developer ID (Tier A).
security import "$workdir/identity.p12" -k "$KEYCHAIN" -P "$p12_pass" \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null

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
