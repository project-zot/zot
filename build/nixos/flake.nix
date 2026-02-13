{
  description = "zot - A production-ready vendor-neutral OCI image registry";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        # Get version information from git or set defaults
        releaseTag = builtins.getEnv "RELEASE_TAG";
        commit = builtins.getEnv "COMMIT";
        goVersion = builtins.getEnv "GO_VERSION";
        
        # Build labels for extensions
        buildLabels = builtins.getEnv "BUILD_LABELS";
        extensions = if buildLabels != "" then buildLabels else "sync,search,scrub,metrics,lint,ui,mgmt,profile,userprefs,imagetrust,events";
        
      in
      {
        packages = {
          default = self.packages.${system}.zot;
          
          zot = pkgs.buildGoModule rec {
            pname = "zot";
            version = if releaseTag != "" then releaseTag else "dev";

            src = ../..;

            # Update this hash when dependencies change
            # Run: nix build .#zot 2>&1 | grep "got:" to get the correct hash
            vendorHash = null; # or specify the hash like: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

            subPackages = [ "cmd/zot" ];

            tags = pkgs.lib.strings.splitString "," extensions;

            ldflags = [
              "-s"
              "-w"
              "-X github.com/project-zot/zot/pkg/api/config.ReleaseTag=${version}"
              "-X github.com/project-zot/zot/pkg/api/config.Commit=${if commit != "" then commit else "unknown"}"
              "-X github.com/project-zot/zot/pkg/api/config.BinaryType=-${extensions}"
              "-X github.com/project-zot/zot/pkg/api/config.GoVersion=${if goVersion != "" then goVersion else "unknown"}"
            ];

            # Disable CGO for static binary
            CGO_ENABLED = "0";

            meta = with pkgs.lib; {
              description = "A production-ready vendor-neutral OCI image registry";
              homepage = "https://zotregistry.io";
              license = licenses.asl20;
              maintainers = [ ];
              mainProgram = "zot";
            };
          };

          zot-minimal = pkgs.buildGoModule rec {
            pname = "zot-minimal";
            version = if releaseTag != "" then releaseTag else "dev";

            src = ../..;

            vendorHash = null;

            subPackages = [ "cmd/zot" ];

            tags = [ ];

            ldflags = [
              "-s"
              "-w"
              "-X github.com/project-zot/zot/pkg/api/config.ReleaseTag=${version}"
              "-X github.com/project-zot/zot/pkg/api/config.Commit=${if commit != "" then commit else "unknown"}"
              "-X github.com/project-zot/zot/pkg/api/config.BinaryType=minimal"
              "-X github.com/project-zot/zot/pkg/api/config.GoVersion=${if goVersion != "" then goVersion else "unknown"}"
            ];

            CGO_ENABLED = "0";

            meta = with pkgs.lib; {
              description = "A production-ready vendor-neutral OCI image registry (minimal build)";
              homepage = "https://zotregistry.io";
              license = licenses.asl20;
              maintainers = [ ];
              mainProgram = "zot";
            };
          };

          zli = pkgs.buildGoModule rec {
            pname = "zli";
            version = if releaseTag != "" then releaseTag else "dev";

            src = ../..;

            vendorHash = null;

            subPackages = [ "cmd/zli" ];

            tags = pkgs.lib.strings.splitString "," "${extensions},search";

            ldflags = [
              "-s"
              "-w"
              "-X github.com/project-zot/zot/pkg/api/config.Commit=${if commit != "" then commit else "unknown"}"
              "-X github.com/project-zot/zot/pkg/api/config.BinaryType=-${extensions}"
              "-X github.com/project-zot/zot/pkg/api/config.GoVersion=${if goVersion != "" then goVersion else "unknown"}"
            ];

            CGO_ENABLED = "0";

            meta = with pkgs.lib; {
              description = "zot registry CLI";
              homepage = "https://zotregistry.io";
              license = licenses.asl20;
              maintainers = [ ];
              mainProgram = "zli";
            };
          };

          zb = pkgs.buildGoModule rec {
            pname = "zb";
            version = if releaseTag != "" then releaseTag else "dev";

            src = ../..;

            vendorHash = null;

            subPackages = [ "cmd/zb" ];

            tags = pkgs.lib.strings.splitString "," extensions;

            ldflags = [
              "-s"
              "-w"
              "-X github.com/project-zot/zot/pkg/api/config.Commit=${if commit != "" then commit else "unknown"}"
              "-X github.com/project-zot/zot/pkg/api/config.BinaryType=-${extensions}"
              "-X github.com/project-zot/zot/pkg/api/config.GoVersion=${if goVersion != "" then goVersion else "unknown"}"
            ];

            CGO_ENABLED = "0";

            meta = with pkgs.lib; {
              description = "zot registry benchmark tool";
              homepage = "https://zotregistry.io";
              license = licenses.asl20;
              maintainers = [ ];
              mainProgram = "zb";
            };
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            git
            gnumake
            skopeo
          ];
        };
      }
    );
}
