{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };

      agent-infra = pkgs.rustPlatform.buildRustPackage {
        pname = "agent-infra";
        version = "0.1.0";
        src = pkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
      };
      in
      {
        packages.default = agent-infra;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ agent-infra ];

          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.claude-code
            pkgs.codex
          ];
        };
      }
    );
}
