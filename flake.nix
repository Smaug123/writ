{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
    nix2container.url = "github:nlewo/nix2container";
    nix2container.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, flake-utils, nix2container, ... }:
    let
      inherit (nixpkgs) lib;

      mkPkgs = system: import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };

      mkRustSource = pkgs:
        let
          sourceRoot = toString ./.;
        in
        pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              rel = lib.removePrefix "${sourceRoot}/" (toString path);
            in
            rel == "Cargo.lock"
            || rel == "Cargo.toml"
            || rel == "src"
            || lib.hasPrefix "src/" rel
            || rel == "crates"
            || lib.hasPrefix "crates/" rel
            || rel == "tests"
            || lib.hasPrefix "tests/" rel;
        };

      mkWrit = pkgs: {
        pname ? "writ",
        cargoBuildFeatures ? [],
        cargoBuildFlags ? [],
        cargoBuildNoDefaultFeatures ? false,
        doCheck ? true
      }:
        pkgs.rustPlatform.buildRustPackage {
          inherit pname;
          version = "0.1.0";
          src = mkRustSource pkgs;
          cargoLock.lockFile = ./Cargo.lock;
          nativeCheckInputs = [ pkgs.git pkgs.procps ];
          inherit cargoBuildFeatures cargoBuildFlags cargoBuildNoDefaultFeatures doCheck;
        };

      guestSystems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

      guestCross = guestSystem: {
        aarch64-linux = {
          pkgsCross = "aarch64-multiplatform-musl";
          rustTarget = "aarch64-unknown-linux-musl";
        };
        x86_64-linux = {
          pkgsCross = "musl64";
          rustTarget = "x86_64-unknown-linux-musl";
        };
      }.${guestSystem} or (throw "unsupported agent VM guest cross target: ${guestSystem}");

      guestArchitecture = guestSystem: {
        aarch64-linux = "arm64";
        x86_64-linux = "amd64";
      }.${guestSystem} or (throw "unsupported agent VM guest system: ${guestSystem}");

      mkCrossWritVm = buildPkgs: guestSystem:
        let
          cross = guestCross guestSystem;
          pkgs = buildPkgs.pkgsCross.${cross.pkgsCross};
          writVm = mkWrit pkgs {
            pname = "writ-vm";
            cargoBuildFeatures = [ "vm-client" ];
            cargoBuildFlags = [ "--bin" "writ-vm" ];
            cargoBuildNoDefaultFeatures = true;
            # Target binaries are not executable on the Darwin builder.
            doCheck = false;
          };
        in
        writVm.overrideAttrs (old: {
          passthru = (old.passthru or {}) // {
            inherit guestSystem;
            rustTarget = cross.rustTarget;
          };
          meta = (old.meta or {}) // {
            description = "Cross-compiled writ-vm guest binary for ${guestSystem}";
          };
        });

      # The broker VM (broker_placement = vm) runs `writd broker`, so its image
      # ships writd built with the `host` feature (the default) rather than the
      # agent's `vm-client`. Cross-compiled to musl for the Linux guest, like
      # writ-vm. NOTE: `host` pulls in keyring/rusqlite/etc.; the broker only ever
      # uses the file secret store, but they must still cross-compile. Verify the
      # build on real guest hardware.
      mkCrossWritd = buildPkgs: guestSystem:
        let
          cross = guestCross guestSystem;
          pkgs = buildPkgs.pkgsCross.${cross.pkgsCross};
          writd = mkWrit pkgs {
            pname = "writd";
            # Default features include `host` (which `writd` requires); build only
            # the writd bin so the broker image doesn't carry the other host bins.
            cargoBuildFlags = [ "--bin" "writd" ];
            # Target binaries are not executable on the Darwin builder.
            doCheck = false;
          };
        in
        writd.overrideAttrs (old: {
          # writd's `host` feature pulls in libsqlite3-sys, ring, zstd-sys, and
          # lzma-sys. Their build.rs scripts compile as host-platform
          # executables, and on darwin rustc's late_link_args for
          # aarch64-apple-darwin include `-liconv`. Cargo's RUSTFLAGS (and
          # CARGO_TARGET_<host>_RUSTFLAGS) do not propagate to build-script
          # rustc invocations in cross-compile mode, so we feed the
          # build-side cc-wrapper directly via NIX_LDFLAGS_<suffixSalt>.
          # writ-vm doesn't need this — vm-client excludes those crates.
          depsBuildBuild = (old.depsBuildBuild or []) ++ [ buildPkgs.libiconv ];
          preBuild =
            let
              salt = pkgs.pkgsBuildBuild.stdenv.cc.suffixSalt;
              varName = "NIX_LDFLAGS_${salt}";
            in ''
              ${old.preBuild or ""}
              export ${varName}="-L${buildPkgs.libiconv}/lib ''${${varName}:-}"
            '';
          passthru = (old.passthru or {}) // {
            inherit guestSystem;
            rustTarget = cross.rustTarget;
          };
          meta = (old.meta or {}) // {
            description = "Cross-compiled writd (host feature) for the broker VM, ${guestSystem}";
          };
        });

      # claude-code in nixpkgs is a thin wrapper around a prebuilt Linux
      # binary downloaded from upstream. The wrapper derivation refuses to
      # build on Darwin (it uses makeBinaryWrapper and autoPatchelfHook), and
      # no public substituter currently caches the aarch64-linux output. Since
      # the upstream artifact is already a self-contained binary, fetch it
      # directly on the build host and lay it out as /bin/claude. The
      # derivation runs on `buildPkgs.system` (e.g. aarch64-darwin) but the
      # file it emits is a Linux executable that the guest VM can run.
      mkGuestClaudeCode = buildPkgs: guestSystem:
        let
          manifest = lib.importJSON
            "${nixpkgs}/pkgs/by-name/cl/claude-code/manifest.json";
          platformKey = {
            aarch64-linux = "linux-arm64-musl";
            x86_64-linux = "linux-x64-musl";
          }.${guestSystem} or (throw
            "unsupported guest system for claude-code: ${guestSystem}");
          platformEntry = manifest.platforms.${platformKey};
          baseUrl = "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases";
          binary = buildPkgs.fetchurl {
            url = "${baseUrl}/${manifest.version}/${platformKey}/claude";
            sha256 = platformEntry.checksum;
          };
          cross = guestCross guestSystem;
          crossPkgs = buildPkgs.pkgsCross.${cross.pkgsCross};
          muslLoaderName = {
            aarch64-linux = "ld-musl-aarch64.so.1";
            x86_64-linux = "ld-musl-x86_64.so.1";
          }.${guestSystem} or (throw
            "unsupported guest system for musl loader: ${guestSystem}");
          muslLoader = "${crossPkgs.musl}/lib/${muslLoaderName}";
        in
        buildPkgs.runCommand "claude-code-${manifest.version}-${guestSystem}"
          {
            nativeBuildInputs = [ buildPkgs.patchelf ];
            passthru = {
              inherit (manifest) version;
              guestSystem = guestSystem;
              platformKey = platformKey;
              muslLoader = muslLoader;
            };
            meta = {
              description =
                "Prebuilt claude-code ${manifest.version} ${platformKey} binary for agent VM guest images";
            };
          }
          ''
            install -Dm0755 ${binary} $out/bin/claude
            # The upstream binary's ELF interpreter is /lib/ld-musl-<arch>.so.1,
            # but the Nix-style guest rootfs has no /lib. Point it at a real
            # store path; nix2container will pull the musl closure into the
            # image automatically.
            patchelf --set-interpreter ${muslLoader} $out/bin/claude
          '';

      mkAgentVmGuestImage = buildPkgs: nix2containerPkgs: {
        guestSystem,
        includeProofTools ? false
      }:
        let
          guestPkgs = mkPkgs guestSystem;
          writVm = mkCrossWritVm buildPkgs guestSystem;
          claudeCode = mkGuestClaudeCode buildPkgs guestSystem;
          imageName =
            if includeProofTools
            then "writ-agent-vm-guest-proof"
            else "writ-agent-vm-guest";
          imageDescription =
            if includeProofTools
            then "Darwin-buildable OCI archive for agent VM proof harnesses"
            else "Darwin-buildable OCI archive for daemon-managed writ agent VMs";
          guestRequiredBins = [
            "awk"
            "claude"
            "codex"
            "curl"
            "diff"
            "find"
            "git"
            "grep"
            "ip"
            "jq"
            "less"
            "nix"
            "ps"
            "rg"
            "sed"
            "sh"
            "writ-vm"
          ];
          guestRequiredBinCheck = lib.concatMapStringsSep "\n"
            (name: ''
              if [ ! -x "${guestRoot}/bin/${name}" ]; then
                echo "guest image is missing required /bin/${name}" >&2
                exit 1
              fi
            '')
            guestRequiredBins;
          # getpwuid_r callers (dotnet/NuGet, git, nix) hang or misbehave
          # without a passwd entry for the running uid; assert one exists.
          guestRequiredEtcCheck = ''
            if [ ! -e "${guestRoot}/etc/passwd" ]; then
              echo "guest image is missing /etc/passwd (getpwuid_r callers like dotnet/NuGet hang)" >&2
              exit 1
            fi
            if ! grep -qE '^[^:]*:[^:]*:0:' "${guestRoot}/etc/passwd"; then
              echo "guest image /etc/passwd has no uid-0 entry" >&2
              exit 1
            fi
          '';
          # grep/sed/awk/find and curl now ship in production (see the guest
          # dev toolset in guestRoot below), so they are no longer forbidden.
          # What stays proof-only is the egress/DNS negative-control set the
          # prove-*.sh harnesses use to demonstrate the no-egress firewall:
          # keeping wget/dig/nslookup out of production preserves a meaningful
          # "proof tools must not leak into prod" regression guard, and curl
          # already covers the routine in-guest HTTP need (it can only reach the
          # broker anyway — the firewall, not tool absence, is the egress
          # boundary).
          productionForbiddenBins = [
            "dig"
            "nslookup"
            "wget"
          ];
          productionForbiddenBinCheck = lib.concatMapStringsSep "\n"
            (name: ''
              if [ -e "${guestRoot}/bin/${name}" ]; then
                echo "production guest image unexpectedly contains /bin/${name}" >&2
                exit 1
              fi
            '')
            productionForbiddenBins;
          # gawk/gnugrep now ship in the production base image, so the proof
          # image inherits them; proofTools only needs to add the egress/DNS
          # probe tools that stay out of production (wget, dig, nslookup).
          proofTools = [
            guestPkgs.bind.dnsutils
            guestPkgs.wget
          ];
          proofToolCheck = lib.concatMapStringsSep "\n"
            (name: ''
              if [ ! -x "${guestRoot}/bin/${name}" ]; then
                echo "proof guest image is missing required /bin/${name}" >&2
                exit 1
              fi
            '')
            [ "awk" "grep" "nslookup" "wget" ];
          # Keep these mount points in sync with AGENT_VM_TMPFS_MOUNTS in
          # src/agent_vm_lifecycle.rs. The lifecycle mounts them as tmpfs; the
          # image carries conventional targets so the rootfs is sane even before
          # runtime mounts are applied.
          guestRuntimeDirs = buildPkgs.runCommand "writ-agent-vm-guest-runtime-dirs" {} ''
            install -d -m 1777 $out/tmp
            install -d -m 1777 $out/var/tmp
            install -d -m 0755 $out/run
            install -d -m 0700 $out/root
          '';
          # Without an /etc/passwd entry for the running uid, any getpwuid_r
          # caller wedges the guest. Concretely: `dotnet restore` (e.g. the
          # csharp-sidecar build spawned from a crate build.rs) loads NuGet
          # settings -> NuGetEnvironment.GetNuGetTempDirectory ->
          # Interop.Sys.GetUserNameFromPasswd, which throws IOException when the
          # uid has no passwd entry; NuGet's ConcurrencyUtilities.ExecuteWithFileLocked
          # then swallows it and retries under a Thread.Sleep forever. The guest
          # runs as root (uid 0), so a single root entry suffices.
          guestEtcFiles = buildPkgs.runCommand "writ-agent-vm-guest-etc-files" {} ''
            install -d $out/etc
            printf 'root:x:0:0:root:/root:/bin/sh\n' > $out/etc/passwd
            printf 'root:x:0:\n' > $out/etc/group
          '';
          guestRoot = buildPkgs.buildEnv {
            name = "writ-agent-vm-guest-root";
            paths = [
              writVm
              claudeCode
              guestEtcFiles
              guestPkgs.bash
              guestPkgs.cacert
              guestPkgs.codex
              guestPkgs.coreutils
              # Routine development toolset. The agent shells out to these during
              # real work (curl for HTTP against the broker, the text/search/JSON
              # utilities in Bash one-liners); the image is minimal by intent but
              # a bare coreutils+git+nix rootfs is too sparse to develop in. The
              # egress/DNS probe tools (wget/dig/nslookup) stay proof-only — see
              # productionForbiddenBins above.
              guestPkgs.curl
              guestPkgs.diffutils
              guestPkgs.findutils
              guestPkgs.gawk
              guestPkgs.gitMinimal
              guestPkgs.gnugrep
              guestPkgs.gnused
              guestPkgs.iproute2
              guestPkgs.jq
              guestPkgs.less
              guestPkgs.nix
              guestPkgs.procps
              guestPkgs.ripgrep
            ] ++ lib.optionals includeProofTools proofTools;
            pathsToLink = [
              "/bin"
              "/etc"
            ];
          };
          image = nix2containerPkgs.nix2container.buildImage {
            name = imageName;
            tag = "latest";
            copyToRoot = [ guestRuntimeDirs guestRoot ];
            arch = guestArchitecture guestSystem;
            perms = [
              {
                path = guestRuntimeDirs;
                regex = ".*/tmp$|.*/var/tmp$";
                mode = "1777";
              }
              {
                path = guestRuntimeDirs;
                regex = ".*/var$|.*/run$";
                mode = "0755";
              }
              {
                path = guestRuntimeDirs;
                regex = ".*/root$";
                mode = "0700";
              }
            ];
            config = {
              Cmd = [ "/bin/sh" ];
              Env = [
                "PATH=/bin"
                "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
                "GIT_SSL_CAINFO=/etc/ssl/certs/ca-bundle.crt"
                "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
                # The SDK's background advertising-manifest updater fires on
                # `dotnet build`/restore and reaches out to nuget.org; in a
                # no-egress guest that just fails quietly in the background. Turn
                # it off so the build does no pointless network work. (It was a
                # second victim of the missing-/etc/passwd hang above.)
                "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true"
                # The whole guest VM is the sandbox boundary (the broker + human
                # review are the trust boundary, never the guest), so Claude Code
                # may run with permissions bypassed. It refuses
                # `--permission-mode bypassPermissions` under uid 0 unless marked
                # sandboxed; the daemon already sets this for the agent run
                # (writ-vm.rs), and setting it image-wide makes a hand-run
                # `claude` in a debug shell behave the same.
                "IS_SANDBOX=1"
              ];
              WorkingDir = "/";
            };
          };
        in
        buildPkgs.runCommand "${imageName}-${guestSystem}.oci.tar"
          {
            passthru.includedProofTools = includeProofTools;
            passthru.imageName = imageName;
            passthru.imageTag = "latest";
            passthru.image = image;
            meta.description = imageDescription;
          }
          ''
            ${guestRequiredBinCheck}
            ${guestRequiredEtcCheck}
            ${lib.optionalString includeProofTools proofToolCheck}
            ${lib.optionalString (!includeProofTools) productionForbiddenBinCheck}
            ${image.copyTo}/bin/copy-to oci-archive:$out:${imageName}:latest
          '';

      # The broker VM image (broker_placement = vm). It runs `writd broker`
      # (launched by the daemon with the route-fix prologue and the mounted
      # config/spec/bearer/secrets), reaching GitHub / Anthropic / nix upstream
      # over its egress interface. Guest-path contract from broker_vm.rs: writd on
      # PATH, /bin/git, /bin/nix, ip (route-fix prologue), and /bin/writ-git-askpass
      # echoing the minted token from token_env (WRIT_GIT_TOKEN by default).
      mkBrokerVmImage = buildPkgs: nix2containerPkgs: { guestSystem }:
        let
          guestPkgs = mkPkgs guestSystem;
          writd = mkCrossWritd buildPkgs guestSystem;
          imageName = "writ-broker-vm";
          # git invokes GIT_ASKPASS for both the username and password prompts (the
          # clone URL embeds no credentials). GitHub App installation tokens
          # authenticate as `x-access-token:<token>`, so answer the username prompt
          # with `x-access-token` and the password prompt with the minted token the
          # broker placed in WRIT_GIT_TOKEN. Assumes the default token_env; a
          # non-default token_env needs a matching askpass.
          brokerAskpass = buildPkgs.writeTextFile {
            name = "writ-git-askpass";
            destination = "/bin/writ-git-askpass";
            executable = true;
            text = ''
              #!/bin/sh
              case "$1" in
                Username*) printf 'x-access-token\n' ;;
                *) printf '%s\n' "''${WRIT_GIT_TOKEN:-}" ;;
              esac
            '';
          };
          brokerRequiredBins = [ "git" "ip" "nix" "sh" "writ-git-askpass" "writd" ];
          brokerRequiredBinCheck = lib.concatMapStringsSep "\n"
            (name: ''
              if [ ! -x "${brokerRoot}/bin/${name}" ]; then
                echo "broker image is missing required /bin/${name}" >&2
                exit 1
              fi
            '')
            brokerRequiredBins;
          # git and nix call getpwuid_r; without a passwd entry for uid 0 they can
          # hang or misbehave (same hazard as the agent guest).
          brokerRequiredEtcCheck = ''
            if ! grep -qE '^[^:]*:[^:]*:0:' "${brokerRoot}/etc/passwd"; then
              echo "broker image /etc/passwd has no uid-0 entry" >&2
              exit 1
            fi
          '';
          # Conventional writable targets; the daemon mounts /tmp, /run, /var/tmp as
          # tmpfs (BROKER_VM_TMPFS_MOUNTS) and the broker work_root lives under /tmp.
          brokerRuntimeDirs = buildPkgs.runCommand "writ-broker-vm-runtime-dirs" {} ''
            install -d -m 1777 $out/tmp
            install -d -m 1777 $out/var/tmp
            install -d -m 0755 $out/run
            install -d -m 0700 $out/root
          '';
          brokerEtcFiles = buildPkgs.runCommand "writ-broker-vm-etc-files" {} ''
            install -d $out/etc/ssl/certs
            printf 'root:x:0:0:root:/root:/bin/sh\n' > $out/etc/passwd
            printf 'root:x:0:\n' > $out/etc/group
            # The broker spawns git through run_clean_git, which clears the
            # environment — so the image-level SSL_CERT_FILE/GIT_SSL_CAINFO do NOT
            # reach git. The Nixpkgs curl/OpenSSL stack then looks for the CA bundle
            # at the default /etc/ssl/certs/ca-certificates.crt, which cacert does
            # not provide (only ca-bundle.crt); link it so HTTPS clones validate.
            ln -s ${guestPkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
              $out/etc/ssl/certs/ca-certificates.crt
          '';
          brokerRoot = buildPkgs.buildEnv {
            name = "writ-broker-vm-root";
            paths = [
              writd
              brokerAskpass
              brokerEtcFiles
              guestPkgs.bash
              guestPkgs.cacert
              guestPkgs.coreutils
              guestPkgs.gitMinimal
              guestPkgs.iproute2
              guestPkgs.nix
            ];
            pathsToLink = [
              "/bin"
              "/etc"
            ];
          };
          image = nix2containerPkgs.nix2container.buildImage {
            name = imageName;
            tag = "latest";
            copyToRoot = [ brokerRuntimeDirs brokerRoot ];
            arch = guestArchitecture guestSystem;
            perms = [
              {
                path = brokerRuntimeDirs;
                regex = ".*/tmp$|.*/var/tmp$";
                mode = "1777";
              }
              {
                path = brokerRuntimeDirs;
                regex = ".*/var$|.*/run$";
                mode = "0755";
              }
              {
                path = brokerRuntimeDirs;
                regex = ".*/root$";
                mode = "0700";
              }
            ];
            config = {
              # The daemon overrides the command with the route-fix prologue +
              # `writd broker …`; this is only a sane default for a debug shell.
              Cmd = [ "/bin/sh" ];
              Env = [
                "PATH=/bin"
                "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
                "GIT_SSL_CAINFO=/etc/ssl/certs/ca-bundle.crt"
                "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
              ];
              WorkingDir = "/";
            };
          };
        in
        buildPkgs.runCommand "${imageName}-${guestSystem}.oci.tar"
          {
            passthru.imageName = imageName;
            passthru.imageTag = "latest";
            passthru.image = image;
            meta.description =
              "Darwin-buildable OCI archive for the writ broker VM (broker_placement = vm)";
          }
          ''
            ${brokerRequiredBinCheck}
            ${brokerRequiredEtcCheck}
            ${image.copyTo}/bin/copy-to oci-archive:$out:${imageName}:latest
          '';
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = mkPkgs system;
        nix2containerPkgs = nix2container.packages.${system};

        writ = mkWrit pkgs {};

        defaultGuestSystem =
          if pkgs.stdenv.hostPlatform.isAarch64
          then "aarch64-linux"
          else "x86_64-linux";

        guestImagePackages = lib.listToAttrs (map
          (guestSystem: {
            name = "agent-vm-guest-image-${guestSystem}";
            value = mkAgentVmGuestImage pkgs nix2containerPkgs {
              inherit guestSystem;
            };
          })
          guestSystems);
        guestProofImagePackages = lib.listToAttrs (map
          (guestSystem: {
            name = "agent-vm-guest-proof-image-${guestSystem}";
            value = mkAgentVmGuestImage pkgs nix2containerPkgs {
              inherit guestSystem;
              includeProofTools = true;
            };
          })
          guestSystems);
        crossGuestBinaryPackages = lib.listToAttrs (map
          (guestSystem: {
            name = "agent-vm-writ-vm-${guestSystem}-musl";
            value = mkCrossWritVm pkgs guestSystem;
          })
          guestSystems);
        brokerImagePackages = lib.listToAttrs (map
          (guestSystem: {
            name = "broker-vm-image-${guestSystem}";
            value = mkBrokerVmImage pkgs nix2containerPkgs {
              inherit guestSystem;
            };
          })
          guestSystems);
        crossBrokerBinaryPackages = lib.listToAttrs (map
          (guestSystem: {
            name = "broker-vm-writd-${guestSystem}-musl";
            value = mkCrossWritd pkgs guestSystem;
          })
          guestSystems);
      in
      {
        packages = guestImagePackages // guestProofImagePackages // crossGuestBinaryPackages // brokerImagePackages // crossBrokerBinaryPackages // {
          default = writ;
          agent-vm-guest-image = mkAgentVmGuestImage pkgs nix2containerPkgs {
            guestSystem = defaultGuestSystem;
          };
          agent-vm-guest-proof-image = mkAgentVmGuestImage pkgs nix2containerPkgs {
            guestSystem = defaultGuestSystem;
            includeProofTools = true;
          };
          agent-vm-writ-vm-musl = mkCrossWritVm pkgs defaultGuestSystem;
          broker-vm-image = mkBrokerVmImage pkgs nix2containerPkgs {
            guestSystem = defaultGuestSystem;
          };
          broker-vm-writd-musl = mkCrossWritd pkgs defaultGuestSystem;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ writ ];

          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.git
            pkgs.claude-code
            pkgs.codex
          ];
        };
      }
    );
}
