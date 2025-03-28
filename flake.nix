{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, nix-filter, rust-overlay, crane, advisory-db, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [
            (import rust-overlay)
            (final: prev: {
              nix-filter = nix-filter.lib;
              rust-toolchain = pkgs.rust-bin.stable.latest.default;
              rust-dev-toolchain = pkgs.rust-toolchain.override {
                extensions = [ "rust-src" "rust-analyzer" ];
              };
            })
          ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          craneLib =
            (crane.mkLib pkgs).overrideToolchain pkgs.rust-toolchain;
          lib = pkgs.lib;
          commonNativeBuildInputs = with pkgs; [
            rustPlatform.bindgenHook
            pkg-config
          ];
          commonBuildInputs = with pkgs;[
            libiconv
            libtool
            libxml2
            libxslt
            xmlsec
            openssl
            llvmPackages.libclang
          ];
          fixtureFilter = path: _type:
            builtins.match ".*test_vectors.*" path != null ||
            builtins.match ".*\.h" path != null;
          sourceAndFixtures = path: type:
            (fixtureFilter path type) || (craneLib.filterCargoSources path type);
          src = lib.cleanSourceWith {
            src = ./.;
            filter = sourceAndFixtures;
          };
          commonArgs = {
            inherit src;

            nativeBuildInputs = commonNativeBuildInputs;
            buildInputs = commonBuildInputs;
          };
          # Build *just* the cargo dependencies, so we can reuse
          # all of that work (e.g. via cachix) when running in CI
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          samael = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        {
          # `nix build`
          packages.default = samael;

          # `nix develop`
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [ rust-dev-toolchain nixpkgs-fmt ] ++ commonBuildInputs;
            nativeBuildInputs = commonNativeBuildInputs;
            shellHook = ''
              export DIRENV_LOG_FORMAT=""
            '';
          };

          checks = {
            # Build the crate as part of `nix flake check` for convenience
            inherit samael;

            # Run clippy (and deny all warnings) on the crate source,
            # again, resuing the dependency artifacts from above.
            #
            # Note that this is done as a separate derivation so that
            # we can block the CI if there are issues here, but not
            # prevent downstream consumers from building our crate by itself.
            samael-clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets"; #--  --deny warnings
            });

            samael-doc = craneLib.cargoDoc (commonArgs // {
              inherit cargoArtifacts;
            });

            # Check formatting
            samael-fmt = craneLib.cargoFmt {
              inherit src;
            };

            # Audit dependencies
            samael-audit = craneLib.cargoAudit {
              inherit src advisory-db;
            };

            # Run tests with cargo-nextest
            # Consider setting `doCheck = false` on `samael` if you do not want
            # the tests to run twice
            samael-nextest = craneLib.cargoNextest (commonArgs // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
            });
          };
        });
}
