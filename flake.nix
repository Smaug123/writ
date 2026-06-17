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
            "claude"
            "codex"
            "git"
            "ip"
            "nix"
            "ps"
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
          productionForbiddenBins = [
            "awk"
            "dig"
            "find"
            "grep"
            "nslookup"
            "sed"
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
          proofTools = [
            guestPkgs.bind.dnsutils
            guestPkgs.gawk
            guestPkgs.gnugrep
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
              guestPkgs.gitMinimal
              guestPkgs.iproute2
              guestPkgs.nix
              guestPkgs.procps
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
      in
      {
        packages = guestImagePackages // guestProofImagePackages // crossGuestBinaryPackages // {
          default = writ;
          agent-vm-guest-image = mkAgentVmGuestImage pkgs nix2containerPkgs {
            guestSystem = defaultGuestSystem;
          };
          agent-vm-guest-proof-image = mkAgentVmGuestImage pkgs nix2containerPkgs {
            guestSystem = defaultGuestSystem;
            includeProofTools = true;
          };
          agent-vm-writ-vm-musl = mkCrossWritVm pkgs defaultGuestSystem;
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
