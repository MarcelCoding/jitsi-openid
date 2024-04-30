{ pkgs, cargoToml, ... }:
let
  manifest = (pkgs.lib.importTOML cargoToml).package;
in
pkgs.rustPlatform.buildRustPackage {
  pname = manifest.name;
  version = manifest.version;
  cargoLock.lockFile = ./Cargo.lock;
  src = pkgs.lib.cleanSource ./.;
  cargoBuildFlags = "-p ${manifest.name}";
}
