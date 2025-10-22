{
  description = "Flake for NumRS2 devShell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    fenix,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      config.allowUnfree = true;
    };
    fenixPkgs = fenix.packages.${system};
    # rustToolchain = with fenixPkgs;
    #   combine [
    #     stable.rustc
    #     stable.cargo
    #     stable.clippy
    #     stable.rust-analyzer
    #     stable.rustfmt
    #   ];
    rustToolchain = fenixPkgs.default.toolchain;
  in {
    inherit fenixPkgs;
    devShells.${system}.default = pkgs.mkShell rec {
      nativeBuildInputs = with pkgs; [
      ];
      buildInputs = with pkgs; [
        rustToolchain
      ];
      LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;
    };
  };
}
