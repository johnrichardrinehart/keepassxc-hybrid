{
  description = "Answer WebAuthn hybrid (caBLE) QR codes with KeePassXC passkeys";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      overlays.default = final: prev: {
        keepassxc-hybrid = final.callPackage ./package.nix { };
        # Lets passkeys-get sign the browser's client data hash, which
        # sign-ins through keepassxc-hybrid need.
        keepassxc = prev.keepassxc.overrideAttrs (old: {
          patches = (old.patches or [ ]) ++ [ ./patches/keepassxc-passkeys-client-data-hash.patch ];
        });
      };

      packages = forAllSystems (
        pkgs:
        let
          applied = self.overlays.default pkgs pkgs;
        in
        {
          default = applied.keepassxc-hybrid;
          inherit (applied) keepassxc-hybrid keepassxc;
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.keepassxc-hybrid ];
          packages = [
            pkgs.cargo
            pkgs.clippy
            pkgs.rustc
            pkgs.rustfmt
            # scripts/live-test.sh
            pkgs.dbus
            pkgs.grim
            pkgs.jq
            pkgs.sway
            pkgs.wtype
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
