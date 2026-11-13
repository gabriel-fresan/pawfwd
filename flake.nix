{
  description = "PawFwd: port forwarding over a dedicated WireGuard tunnel";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Tools the program calls through PATH: wg/wg-quick, nft, ip/ss, ssh, sysctl.
      runtimeDeps =
        pkgs: with pkgs; [
          wireguard-tools
          nftables
          iproute2
          openssh
          procps
        ];
    in
    {
      packages = forAllSystems (pkgs: {
        pawfwd = pkgs.python3Packages.buildPythonApplication {
          pname = "pawfwd";
          version = "2.2.0";
          pyproject = true;

          src = ./.;

          build-system = [ pkgs.python3Packages.setuptools ];
          nativeCheckInputs = [ pkgs.python3Packages.pytestCheckHook ];

          makeWrapperArgs = [
            "--prefix"
            "PATH"
            ":"
            (pkgs.lib.makeBinPath (runtimeDeps pkgs))
          ];

          meta = {
            description = "Port forwarding over a dedicated WireGuard tunnel";
            homepage = "https://github.com/gabriel-fresan/pawfwd";
            license = pkgs.lib.licenses.mit;
            mainProgram = "pawfwd";
            platforms = pkgs.lib.platforms.linux;
          };
        };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.pawfwd;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [
              ps.pytest
              ps.setuptools
            ]))
            pkgs.ruff
          ]
          ++ runtimeDeps pkgs;
        };
      });
    };
}
