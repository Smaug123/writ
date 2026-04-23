{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };

      writ = pkgs.rustPlatform.buildRustPackage {
        pname = "writ";
        version = "0.1.0";
        src = pkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
      };
      in
      {
        packages.default = writ;

        devShells.default = pkgs.mkShell {
          inputsFrom = [ writ ];

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
