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

      mkAgentVmGuestImage = buildPkgs: nix2containerPkgs: guestSystem:
        let
          guestPkgs = mkPkgs guestSystem;
          writVm = mkCrossWritVm buildPkgs guestSystem;
          guestRoot = buildPkgs.buildEnv {
            name = "writ-agent-vm-guest-root";
            paths = [
              writVm
              guestPkgs.bash
              guestPkgs.bind.dnsutils
              guestPkgs.cacert
              guestPkgs.coreutils
              guestPkgs.findutils
              guestPkgs.gawk
              guestPkgs.gitMinimal
              guestPkgs.gnugrep
              guestPkgs.gnused
              guestPkgs.iproute2
              guestPkgs.wget
            ];
            pathsToLink = [
              "/bin"
              "/etc"
            ];
          };
          image = nix2containerPkgs.nix2container.buildImage {
            name = "writ-agent-vm-guest";
            tag = "latest";
            copyToRoot = [ guestRoot ];
            arch = guestArchitecture guestSystem;
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
        buildPkgs.runCommand "writ-agent-vm-guest-${guestSystem}.oci.tar"
          {
            passthru.imageName = "writ-agent-vm-guest";
            passthru.imageTag = "latest";
            passthru.image = image;
            meta.description = "Darwin-buildable OCI archive for daemon-managed writ agent VMs";
          }
          ''
            ${image.copyTo}/bin/copy-to oci-archive:$out:writ-agent-vm-guest:latest
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
            value = mkAgentVmGuestImage pkgs nix2containerPkgs guestSystem;
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
        packages = guestImagePackages // crossGuestBinaryPackages // {
          default = writ;
          agent-vm-guest-image = mkAgentVmGuestImage pkgs nix2containerPkgs defaultGuestSystem;
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
