{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = (import nixpkgs) {
            inherit system;
          };
        in
        {
          packages = rec {
            jitsi-openid = pkgs.callPackage ./derivation.nix {
              cargoToml = ./Cargo.toml;
            };
            default = jitsi-openid;
          };


          devShells = {
            default = pkgs.mkShell {
              nativeBuildInputs = with pkgs; [ pkg-config ];
              buildInputs = with pkgs; [ openssl ];
            };
          };
        }
      ) // {
      overlays.default = _: prev: {
        jitsi-openid = self.packages."${prev.system}".default;
      };

      nixosModules = rec {
        jitsi-openid = import ./module.nix;
        default = jitsi-openid;
      };
    };
}
