{
  description = "Flake for neptune-core";

  inputs = {
    nixpks.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    naersk,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };
        rust = pkgs.rust-bin.selectLatestNightlyWith (
          toolchain:
            toolchain.default.override {
              extensions = [
                "rust-src"
                "rust-analyzer"
                "miri"
              ];
              targets = ["x86_64-unknown-linux-gnu"];
            }
        );
        naerskLib = pkgs.callPackage naersk {
          cargo = rust;
          rustc = rust;
        };

        buildInputs = with pkgs; [
          rust
          cmake
          pkg-config
          openssl
        ];
        tooling = with pkgs; [
          cargo-nextest
          cargo-mutants
          alejandra # Nix code formatter
          deadnix # Nix Dead code detection
          statix # Nix static checks
          taplo # Toml toolkit and formatter
        ];
      in
        with pkgs; {
          # Build the packages with `nix build` or `nix build .#neptune-core`
          packages = rec {
            default = neptune-core;
            neptune-core = naerskLib.buildPackage {
              pname = "neptune-core";
              src = ./.;
              inherit buildInputs;
            };
            neptune-core-cli = naerskLib.buildPackage {
              pname = "neptune-core-cli";
              src = ./.;
              inherit buildInputs;
            };
          };
          # Run the packages with `nix run` or `nix run .#neptune-core`
          apps = rec {
            default = neptune-core;
            neptune-core = flake-utils.lib.mkApp {
              drv = self.packages.${system}.neptune-core;
            };
            neptune-core-cli = flake-utils.lib.mkApp {
              drv = self.packages.${system}.neptune-core;
            };
          };
          # Enter the reproducible development shell using `nix develop`
          devShells.default = mkShell {
            buildInputs = buildInputs ++ tooling;
          };
        }
    );
}
