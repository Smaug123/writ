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
          nativeCheckInputs = [ pkgs.git ];
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

      mkAgentVmGuestImage = buildPkgs: nix2containerPkgs: {
        guestSystem,
        includeProofTools ? false
      }:
        let
          guestPkgs = mkPkgs guestSystem;
          writVm = mkCrossWritVm buildPkgs guestSystem;
          imageName =
            if includeProofTools
            then "writ-agent-vm-guest-proof"
            else "writ-agent-vm-guest";
          imageDescription =
            if includeProofTools
            then "Darwin-buildable OCI archive for agent VM proof harnesses"
            else "Darwin-buildable OCI archive for daemon-managed writ agent VMs";
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
          guestRoot = buildPkgs.buildEnv {
            name = "writ-agent-vm-guest-root";
            paths = [
              writVm
              guestPkgs.bash
              guestPkgs.cacert
              guestPkgs.coreutils
              guestPkgs.gitMinimal
              guestPkgs.iproute2
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
