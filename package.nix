{
  lib,
  rustPlatform,
  pkg-config,
  dbus,
  openssl,
}:

rustPlatform.buildRustPackage {
  pname = "keepassxc-hybrid";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tests
    ];
  };

  cargoHash = "sha256-3/7hH34B3M0ZXwaq5BvWYlfswn+ge0b1kKiBReNdiTU=";

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    dbus
    openssl
  ];

  meta = {
    description = "Answer WebAuthn hybrid (caBLE) QR codes with KeePassXC passkeys";
    homepage = "https://github.com/johnrichardrinehart/keepassxc-hybrid";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "keepassxc-hybrid";
  };
}
