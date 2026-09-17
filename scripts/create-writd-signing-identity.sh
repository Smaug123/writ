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

Expect two one-time macOS dialogs:
  1. This script marks the new certificate trusted for code signing (user
     trust domain, code-signing policy only); macOS asks for your login
     password. Without this step codesign refuses the identity outright
     ("no identity found"): codesign signs only with *valid* identities, and
     a self-signed certificate is valid only once trusted.
  2. The first time codesign uses the key (scripts/install-macos.sh) macOS
     asks you to authorise it; click "Always Allow" and it will not ask again.

Environment overrides:
  WRIT_SIGN_IDENTITY_CN  certificate common name (default: "org.writ.writd signing")
  WRIT_SIGN_KEYCHAIN     keychain to import into (default: the login keychain)

Re-running replaces the identity with a fresh certificate (and asks for trust
again, since trust is per certificate); re-run scripts/install-macos.sh and
scripts/allow-writd-firewall.sh afterwards. The old certificate's
trust-settings entry is left behind — harmless, since its private key is
destroyed, but removable via Keychain Access if you prefer tidiness.

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

# Pin macOS's own openssl (LibreSSL). OpenSSL 3 — which Homebrew or a Nix
# profile can put ahead of it on PATH — exports PKCS#12 with PBES2/AES defaults
# that macOS's `security import` cannot read, so a PATH-dependent openssl would
# make identity creation fail (and, since we delete the old identity first,
# leave none on a rerun). If overriding WRIT_OPENSSL, use a LibreSSL- or
# OpenSSL-1.x-compatible build, or one where the p12 export is macOS-importable.
OPENSSL="${WRIT_OPENSSL:-/usr/bin/openssl}"
command -v "$OPENSSL" >/dev/null 2>&1 || { echo "error: openssl not found at '$OPENSSL' (set WRIT_OPENSSL)" >&2; exit 1; }
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

"$OPENSSL" req -x509 -newkey rsa:2048 -nodes \
  -keyout "$workdir/key.pem" -out "$workdir/cert.pem" \
  -days 3650 -config "$workdir/ext.cnf" >/dev/null 2>&1

# security import wants a PKCS#12 bundle for a cert+key pair.
p12_pass="$("$OPENSSL" rand -hex 16)"
"$OPENSSL" pkcs12 -export -inkey "$workdir/key.pem" -in "$workdir/cert.pem" \
  -name "$CN" -out "$workdir/identity.p12" -passout "pass:${p12_pass}" >/dev/null 2>&1

# Re-running must replace, not accumulate: `security import` does not remove a
# previous cert+key with the same name, and two identities sharing a common
# name make `codesign --sign "$CN"` ambiguous (it refuses). Delete any prior
# identity whose common name is EXACTLY "$CN", by SHA-1 fingerprint. Matching
# must be exact: both `grep -F "$CN"` and `delete-identity -c "$CN"` match
# substrings, so a default run would otherwise destroy an unrelated identity
# such as one created with a "$CN ..." CN override. find-identity prints each
# identity as `  N) <40-hex-sha1> "<name>" (...)`; the surrounding quotes make
# `"$CN"` a whole-name match, and -Z deletes exactly that certificate.
while :; do
  # `|| true`: grep exits non-zero when nothing matches, and pipefail + set -e
  # would otherwise abort the whole script on the empty-keychain first run.
  fp="$(security find-identity -p codesigning "$KEYCHAIN" \
    | grep -F "\"${CN}\"" | grep -oE '[0-9A-Fa-f]{40}' | head -n1 || true)"
  [[ -n "$fp" ]] || break
  security delete-identity -Z "$fp" "$KEYCHAIN" >/dev/null 2>&1 || break
done

# -T /usr/bin/codesign adds codesign to the key's access-control list, so the
# first signing prompts once for "Always Allow" rather than being denied. We do
# NOT touch the keychain's partition list: an unscoped `set-key-partition-list`
# rewrites every key in a shared login keychain and can strip other apps'
# access to their own keys, and a reliably-scoped form is not available. A
# one-time interactive "Always Allow" is the safe path here; automated/CI
# signing should use a dedicated keychain or an Apple Developer ID (Tier A).
security import "$workdir/identity.p12" -k "$KEYCHAIN" -P "$p12_pass" -f pkcs12 \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null

# codesign signs only with *valid* identities, and a self-signed certificate
# is not valid until it is trusted — untrusted, `codesign --sign <sha1>` fails
# with "no identity found". Trust it in the user domain (no -d: the admin
# domain needs sudo and machine-wide scope), restricted to the code-signing
# policy. macOS asks for your login password here. add-trusted-cert matches
# the already-imported certificate rather than duplicating it. Reversible:
#   security remove-trusted-cert <cert.pem>
security add-trusted-cert -r trustRoot -p codeSign -k "$KEYCHAIN" "$workdir/cert.pem" || {
  echo "error: could not mark '${CN}' trusted for code signing (dialog cancelled?)" >&2
  echo "       codesign will refuse the identity until it is trusted; re-run this script." >&2
  exit 1
}

echo "imported code-signing identity into ${KEYCHAIN}:"
# -v: codesign uses only *valid* identities, so demanding validity here turns
# "the trust step did not take" into a hard error now instead of a confusing
# `codesign: no identity found` later. Match the whole quoted name so a
# substring collision cannot masquerade as our identity.
security find-identity -v -p codesigning "$KEYCHAIN" | grep -F "\"${CN}\"" || {
  echo "error: identity '${CN}' not present as a VALID identity after import + trust" >&2
  exit 1
}
echo
echo "next:"
echo "  scripts/install-macos.sh          # installs writd, signs it with this identity"
echo "  scripts/allow-writd-firewall.sh   # one-time firewall allow (needs sudo)"
