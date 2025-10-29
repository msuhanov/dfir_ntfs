{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {inherit system;};

        # create package from setup.py
        dfir_ntfs = pkgs.python3Packages.buildPythonPackage {
          pname = "dfir_ntfs";
          version = "1.1.19";
          src = ./.;
          pyproject = true;
          build-system = [pkgs.python3Packages.setuptools];
        };

        # create ntfs_parser binary
        ntfs_parser =
          pkgs.writers.writePython3Bin "ntfs_parser"
          {
            libraries = [dfir_ntfs];
            doCheck = false; # has to be included to ignore style warnings, which prevent the build
          } (builtins.readFile ./ntfs_parser);

        # create fat_parser binary
        fat_parser =
          pkgs.writers.writePython3Bin "fat_parser"
          {
            libraries = [dfir_ntfs];
            doCheck = false; # has to be included to ignore style warnings, which prevent the build
          } (builtins.readFile ./fat_parser);

        # combine all binaries
        all_binaries = pkgs.symlinkJoin {
          name = "all_binaries";
          paths = [ntfs_parser fat_parser];
        };
      in {
        # entrypoint for `nix build .`
        packages = {
          inherit ntfs_parser fat_parser all_binaries; # provides entrypoints to build the programs on their own, or all of them at once
          default = all_binaries;
        };

        # entrypoint for `nix develop`
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.python3
            dfir_ntfs
          ];
        };
      }
    );
}
