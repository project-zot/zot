# This file provides backward compatibility for non-flake nix commands
# Usage: nix-build build/nixos/default.nix
{ pkgs ? import <nixpkgs> { } }:

let
  # Source the flake outputs
  flake = (import ./flake.nix).outputs {
    self = flake;
    nixpkgs = pkgs;
    flake-utils = import (pkgs.fetchFromGitHub {
      owner = "numtide";
      repo = "flake-utils";
      rev = "v1.0.0";
      sha256 = "sha256-1a2zyLv6TFBFGdLkAZ+Q7jGP5D8xp0ry5A1E2VBqbHw=";
    });
  };
in
flake.packages.${pkgs.system}.zot
