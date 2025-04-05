{ lib, rustPlatform, pkg-config, openssl, ... }:

let
  manifest = (lib.importTOML ./Cargo.toml).package;
in
rustPlatform.buildRustPackage rec {
  pname = manifest.name;
  inherit (manifest) version;

  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;

  cargoBuildFlags = "-p ${pname}";
  cargoTestFlags = "-p ${pname}";

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
  ];

  meta = {
    mainProgram = "jitsi-openid";
  };
}
