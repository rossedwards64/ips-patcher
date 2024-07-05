{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in {
        defaultPackage = naersk-lib.buildPackage ./.;
        devShell = with pkgs;
          mkShell {
            buildInputs =
              [ cargo rustup rustc rustfmt pre-commit rustPackages.clippy ];
            RUST_SRC_PATH = rustPlatform.rustLibSrc;

            shellHook = ''
              export CARGO_HOME=~/.local/share/cargo
              export RUSTUP_HOME=~/.local/share/rustup
              export PATH=$PATH:$RUSTUP_HOME/toolchains/stable-x86_64-w64-unknown-linux-gnu/bin/
              rustup default stable
            '';
          };
      });
}
