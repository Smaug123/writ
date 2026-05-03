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

      mkWrit = pkgs: {
        cargoBuildFeatures ? [],
        cargoBuildFlags ? [],
        cargoBuildNoDefaultFeatures ? false,
        doCheck ? true
      }:
        pkgs.rustPlatform.buildRustPackage {
        pname = "writ";
        version = "0.1.0";
        src = pkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        nativeCheckInputs = [ pkgs.git ];
        inherit cargoBuildFeatures cargoBuildFlags cargoBuildNoDefaultFeatures doCheck;
      };

      guestSystems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

      guestArchitecture = guestSystem: {
        aarch64-linux = "arm64";
        x86_64-linux = "amd64";
      }.${guestSystem} or (throw "unsupported agent VM guest system: ${guestSystem}");

      mkAgentVmGuestImage = guestSystem:
        let
          pkgs = mkPkgs guestSystem;
          writVm = mkWrit pkgs {
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
      in
      {
        packages = guestImagePackages // {
          default = writ;
          agent-vm-guest-image = mkAgentVmGuestImage defaultGuestSystem;
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
