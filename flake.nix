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
        rust = pkgs.rust-bin.stable.latest.default;
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
        mkPackage = pname:
          naerskLib.buildPackage {
            cargoBuildFlags = ["--bin" "${pname}"];
            src = ./.;
            inherit buildInputs pname;
          };
        mkApp = pname:
          flake-utils.lib.mkApp {
            drv = self.packages.${system}.${pname};
          };
      in
        with pkgs; {
          # Build the packages with `nix build` or `nix build .#neptune-core` for example.
          packages = rec {
            default = neptune-core;
            neptune-core = mkPackage "neptune-core";
            neptune-cli = mkPackage "neptune-core-cli";
            neptune-dashboard = mkPackage "neptune-dashboard";
          };
          # Run the packages with `nix run` or `nix run .#neptune-core` for example.
          apps = rec {
            default = neptune-core;
            neptune-core = mkApp "neptune-core";
            neptune-cli = mkApp "neptune-cli";
            neptune-dashboard = mkApp "neptune-dashboard";
          };
          # Enter the reproducible development shell using `nix develop` (automatically done with `direnv allow` if available)
          devShells.default = mkShell {
            buildInputs = buildInputs ++ tooling;
          };
        }
    );
}
