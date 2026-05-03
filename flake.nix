{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
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

      mkAgentVmGuestImage = guestSystem:
        let
          pkgs = mkPkgs guestSystem;
          writVm = mkWrit pkgs {
            pname = "writ-vm";
            cargoBuildFeatures = [ "vm-client" ];
            cargoBuildFlags = [ "--bin" "writ-vm" ];
            cargoBuildNoDefaultFeatures = true;
            doCheck = false;
          };
          guestRoot = pkgs.buildEnv {
            name = "writ-agent-vm-guest-root";
            paths = [
              writVm
              pkgs.bash
              pkgs.bind.dnsutils
              pkgs.cacert
              pkgs.coreutils
              pkgs.findutils
              pkgs.gawk
              pkgs.gitMinimal
              pkgs.gnugrep
              pkgs.gnused
              pkgs.iproute2
              pkgs.wget
            ];
            pathsToLink = [
              "/bin"
              "/etc"
            ];
          };
          dockerArchive = pkgs.dockerTools.buildLayeredImage {
            name = "writ-agent-vm-guest";
            tag = "latest";
            # Apple Container loads this locally, so avoid spending build time compressing it.
            compressor = "none";
            contents = [ guestRoot ];
            architecture = guestArchitecture guestSystem;
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
        pkgs.runCommand "writ-agent-vm-guest-${guestSystem}.oci.tar"
          {
            nativeBuildInputs = [ pkgs.skopeo ];
            passthru.imageName = "writ-agent-vm-guest";
            passthru.imageTag = "latest";
            meta.description = "OCI archive for daemon-managed writ agent VMs";
          }
          ''
            skopeo --insecure-policy copy \
              docker-archive:${dockerArchive} \
              oci-archive:$out:writ-agent-vm-guest:latest
          '';
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = mkPkgs system;

        writ = mkWrit pkgs {};

        defaultGuestSystem =
          if pkgs.stdenv.hostPlatform.isAarch64
          then "aarch64-linux"
          else "x86_64-linux";

        guestImagePackages = lib.listToAttrs (map
          (guestSystem: {
            name = "agent-vm-guest-image-${guestSystem}";
            value = mkAgentVmGuestImage guestSystem;
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
          agent-vm-guest-image = mkAgentVmGuestImage defaultGuestSystem;
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
