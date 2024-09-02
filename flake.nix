{
  outputs = { flake-utils, nixpkgs, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; }; in rec {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "saltcrypt";
          version = "1";
          src = ./.;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            libsodium
          ];

          CFLAGS = "-O3";

          doCheck = true;
          stripDebugFlags = [ "-s" ];
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ packages.default ];
          packages = with pkgs; [
            bear
            clang-tools
          ];
        };
      });
}
