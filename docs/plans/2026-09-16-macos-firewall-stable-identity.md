# A stable code-signing identity for `writd`, so the macOS firewall stops blocking it

Implement this plan with each stage on its own branch, stacked as necessary on
previous branches, so that a reviewer can review each branch in isolation.

## The problem, and why it is the whole "vmnet accept() bug"

The failure that looked for months like an Apple vmnet defect is the macOS
**Application Firewall** (ALF, `socketfilterfw`). It is a per-binary socket
filter. On this host `socketfilterfw --listapps` shows `target/release/writd`
and the nix-built `writd` as **Block incoming connections**, while
`target/debug/writd` is **Allow**. A blocked binary's listener still completes
the TCP handshake and the kernel ACKs the request, but ALF detaches the socket
before `accept()` returns it, so `accept()` hands back a not-connected socket
(`getpeername`→`EINVAL`, `recv`→`ENOTCONN`) — exactly the pure-C repro's
signature. Loopback is exempt (hence debug-vs-release confusion when the two
were tested on different ports), and guest-to-guest is unaffected. Allowing the
repro server in ALF made the repro pass.

So host placement works in a release build **once `writd` is allowed in ALF**.
The remaining problem is that the allow does not stick:

1. **The signature changes every build.** `codesign -dvv` shows the binaries
   are ad-hoc, linker-signed, with `Identifier=writd-<hash>` (the hash differs
   between release `writd-b5512dba216ed996` and debug `writd-a3849f1f8b8eb795`)
   and `TeamIdentifier=not set`. An ad-hoc binary's designated requirement is
   its cdhash, so every rebuild is a different code identity. ALF re-evaluates a
   binary whose stored designated requirement no longer matches, and a new
   identity defaults to blocked.
2. **The path changes every build for the nix output.** ALF keys entries on the
   resolved binary path. `/nix/store/<hash>-writ-.../bin/writd` is a new path
   each build; `target/release/writd` is stable but is a build artifact, not an
   install location.
3. **There is no signing identity to sign with.** `security find-identity -v -p
   codesigning` reports **0 valid identities**.

ALF's own policy is the lever. `socketfilterfw --getallowsigned` reports both
"Automatically allow built-in signed software" and "Automatically allow
downloaded signed software" **ENABLED**. Software signed by an Apple-anchored
**Developer ID** certificate is auto-allowed with no per-app entry; arbitrary
self-signed software is not. That gives two tiers of fix.

## Scope

- **Only `writd` binds a TCP listener** (the broker HTTP and the UI HTTP live in
  `writd`). The `writ` CLI talks to the daemon over a Unix socket, and the
  privileged `writ-agent-vm-pf-helper` runs under `sudo` and binds nothing, so
  neither is subject to ALF. This plan signs `writd`.
- Host placement only. VM placement is WIP and parked; nothing here depends on
  it.
- The lifecycle proof's stand-in broker is a nix-built `python3`, which ALF also
  blocks. That is a proof-environment nuisance, not production, and is handled
  as a footnote in Stage 3, not by signing python.

## Two tiers, and the recommendation

The decision follows the gospel's boundary-cost reasoning: pay for the weakest
mechanism that removes the constraint you actually hit.

- **Tier B (stable self-signed identity + one-time allow).** Free, local, and
  removes the constraint on this and any single operator host today. A
  self-signed cert kept in the login keychain gives `writd` a **stable
  designated requirement** (identifier + that anchor) that survives rebuilds; a
  stable install path gives ALF a stable key; a single `sudo socketfilterfw
  --add/--unblockapp` on that path then sticks across rebuilds. It does **not**
  get ALF's auto-allow (not Apple-anchored), so it keeps one manual firewall
  step, exactly like the existing `/etc/writ/agent-vm-pf-policy.json` and
  `pf.conf` anchor steps.
- **Tier A (Developer ID + notarization).** Costs an Apple Developer Program
  membership ($99/yr) and a notarization step in the release build. In return
  ALF auto-allows `writd` with **no** per-machine firewall step, surviving both
  rebuilds and path changes, on every host. This is the right answer once
  `writ` is distributed to machines you do not control.

**Recommendation:** do Tier B now (Stages 1–3); it unblocks release-build host
placement on the dev host and any self-hosted operator box with one documented
step. Adopt Tier A (Stage 4) only when `writ` ships beyond hosts you configure
by hand. Tier B is not throwaway: its stable install path and identifier are
exactly what Tier A also needs, so Stage 4 replaces only the certificate and
adds notarization.

---

## Stage 1: A stable install path and a stable code-signing identifier

**Dependencies:** None.

**Implements:** Remove causes (1) and (2) — build-varying path and identifier.

Add `scripts/install-macos.sh` (the documented install step, replacing the bare
`install -m 0755 target/release/writd ~/.local/bin/writd` in
`docs/user_facing/getting-started.md`). It installs `writd` to a fixed absolute
path (default `~/.local/bin/writd`, overridable) and then re-signs the installed
copy with a **stable identifier**:

```sh
codesign --force --sign - --identifier org.writ.writd "$dest"   # Stage 1: still ad-hoc
```

Pinning `--identifier` makes the identifier stable across rebuilds even while
the cert is still ad-hoc; Stage 2 swaps `--sign -` for a real identity so the
whole designated requirement stabilises. The daemon is always launched from
this fixed path, never from `target/` or `/nix/store`.

**Correctness oracle:**
- After a build, install, and re-sign, `codesign -dvv $dest` reports
  `Identifier=org.writ.writd`. After a *second* clean build and re-install, the
  identifier is byte-for-byte the same (a script assertion; the cdhash still
  differs at this stage, which is what Stage 2 fixes).
- The script is idempotent and `shellcheck`-clean; `bash -n` passes.
- `docs/user_facing/getting-started.md` points at the script and states that the
  daemon must be run from the fixed path.

---

## Stage 2: A persistent self-signed signing identity

**Dependencies:** Stage 1.

**Implements:** Remove cause (3) and stabilise the full designated requirement,
so a rebuilt-and-reinstalled `writd` satisfies the requirement ALF stored the
first time.

Add `scripts/create-writd-signing-identity.sh`: create a self-signed
code-signing certificate (a `Self-Signed Root` with the code-signing EKU, e.g.
via a `certtool`/`security` sequence or a checked-in openssl config) named
`org.writ.writd signing`, import it into the login keychain, and mark it trusted
for code signing. `scripts/install-macos.sh` then signs with it instead of
ad-hoc:

```sh
codesign --force --options runtime --sign "org.writ.writd signing" \
  --identifier org.writ.writd "$dest"
```

The designated requirement is now `identifier "org.writ.writd" and
certificate leaf = H"<cert sha1>"`, which is **constant across rebuilds**
because both the identifier and the signing cert are fixed. Document that the
private key never leaves the operator's keychain and that losing it just means
re-running this script (a new cert, one new `--add`).

**Correctness oracle:**
- `codesign --verify --strict $dest` passes, and `codesign -d -r- $dest` prints
  a designated requirement naming `org.writ.writd` and a certificate leaf hash.
- Rebuild + reinstall (which re-signs with the same cert) yields the **same**
  `-r-` designated requirement string as before (script assertion). This is the
  property that makes the Stage-3 firewall allow durable.
- `security find-identity -v -p codesigning` lists the new identity.

---

## Stage 3: One documented firewall allow that survives rebuilds

**Dependencies:** Stage 2.

**Implements:** The actual unblock, as a first-class install step alongside the
PF policy file and the `pf.conf` anchor.

Add to `docs/user_facing/getting-started.md` a "macOS Application Firewall" step
and a helper `scripts/allow-writd-firewall.sh`:

```sh
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$dest"
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp "$dest"
```

Because `$dest` and its designated requirement are both stable after Stages 1–2,
this runs **once** and keeps `writd` allowed across every subsequent rebuild and
reinstall. The doc explains the mechanism (ALF is a per-binary socket filter;
loopback is exempt; a blocked `writd` presents as the `accept()`-returns-
not-connected symptom) so the next person does not re-diagnose it, and links the
now-corrected `docs/vmnet-accept-bug-and-broker-vm-plan.md`.

Footnote for `scripts/prove-agent-vm-lifecycle.sh`: its stand-in broker is a
nix-built `python3`, which ALF also blocks, so the proof's broker-reach leg
times out with the signature PR #413 now names. The proof gains an optional
`WRIT_PROVE_ALLOW_BROKER_BIN` that, when set to the python path, runs the same
`--add`/`--unblockapp` on it before the run (and removes it after), so the proof
can go green on a host with ALF enabled without permanently allowing a general
interpreter. This is the proof's positive-control broker only; production
`writd` is covered by the steps above.

**Correctness oracle:**
- `socketfilterfw --getappblocked $dest` reports "permitted" after the script.
- After a clean rebuild + reinstall (no re-run of the allow), `--getappblocked
  $dest` still reports "permitted".
- End-to-end: with a **release** `writd` at `$dest` allowed, and the python
  broker allowed via the proof knob, `scripts/prove-agent-vm-lifecycle.sh`'s
  broker-reach leg passes (no `WRIT_PROVE_TOLERATE_VMNET_ACCEPT_BUG` waiver).
  This is the first release-build green the proof has had since the symptom
  appeared, and it confirms the diagnosis end to end.

---

## Stage 4 (defer until distribution): Developer ID + notarization

**Dependencies:** Stage 1 (path/identifier); replaces Stage 2's certificate.

**Implements:** Tier A — ALF auto-allow, no per-machine firewall step, on hosts
you do not configure.

With an Apple Developer Program membership: obtain a "Developer ID Application"
certificate, sign `writd` with it and the hardened runtime
(`codesign --options runtime --timestamp --sign "Developer ID Application: …"`),
and notarize + staple the release artifact (`notarytool submit --wait` then
`stapler staple`, or notarize a zip of the binary). Because ALF's
"automatically allow downloaded signed software" is enabled by default, a
Developer-ID-signed, notarized `writd` is allowed with no `socketfilterfw` step,
across rebuilds and path changes. Fold the signing + notarization into the
release build (a CI job or a `scripts/release-macos.sh`), not the nix
derivation, since the identity and Apple credentials live outside the build
sandbox.

**Correctness oracle:**
- `codesign -dvv` shows a `Developer ID Application` authority and a set
  `TeamIdentifier`; `spctl -a -vv --type execute $dest` reports `accepted`
  `source=Notarized Developer ID`.
- On a host that has **never** had a `writ` firewall entry, a freshly installed
  notarized `writd` is `--getappblocked` "permitted" with no `--add` run.
- The release build produces the signed, stapled artifact; a `stapler validate`
  check gates the release.

---

## After Stage 3

- The dev host runs release-build host placement without fighting the firewall,
  and the diagnosis in PR #413 / `docs/vmnet-accept-bug-and-broker-vm-plan.md`
  is corrected from "Apple vmnet defect" to "Application Firewall blocks the
  broker binary". Nothing needs to be reported to Apple.
- The `broker_placement = vm` plan (PR #414) loses its urgency argument entirely
  and stays parked WIP, per the decision to keep host placement.
- Stage 4 is the only remaining item, and only if `writ` is distributed.
