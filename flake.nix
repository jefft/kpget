{
  description = "kpget: fetch passwords from KeepassXC, sealed behind a Yubikey challenge-response";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        python = pkgs.python3;

        # keepassxc-proxy-client is not in nixpkgs. Pure Python,
        # setuptools-based (setup.py); fetched from PyPI.
        keepassxc-proxy-client = python.pkgs.buildPythonPackage rec {
          pname = "keepassxc-proxy-client";
          version = "0.1.7";
          pyproject = true;
          build-system = [ python.pkgs.setuptools ];
          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-ZS8MAPOP2UfT7+UCrES4pZzI1MprYlYREPrYNagRB6A=";
          };
          dependencies = [ python.pkgs.pynacl ];
          doCheck = false;
        };
      in {
        packages = rec {
          kpget = python.pkgs.buildPythonApplication rec {
            pname = "kpget";
            version = (pkgs.lib.importTOML ./pyproject.toml).project.version;
            pyproject = true;
            # This flake lives in the kpget repo, so build the repo itself.
            src = self;
            build-system = [ python.pkgs.hatchling ];
            dependencies = [ keepassxc-proxy-client python.pkgs.pynacl ];
            # Tests need a live keepassxc-proxy / Yubikey, so aren't runnable
            # in the Nix build sandbox.
            doCheck = false;
          };

          default = kpget;
        };
      });
}
