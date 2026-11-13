# PawFwd

**P**ackets **A**cross **W**ireGuard, **F**orwarded.

PawFwd publishes services running on a home network (no public IP, or behind CGNAT) through a VPS with a public IP. Traffic enters the VPS, crosses a dedicated WireGuard tunnel and reaches the home server.

```
client ──► VPS (ingress, public IP)
                 │  DNAT + TCP MSS clamp
                 ▼
          dedicated WireGuard tunnel  (10.77.0.0/24)
                 │
                 ▼
          home server (target)
```

If Tailscale is already installed, PawFwd leaves it alone. PawFwd uses its own WireGuard interface and keeps SSH and administration on Tailscale.

> Português: [README.pt-BR.md](README.pt-BR.md)

## Features

- TCP, UDP, or both, with a public port that can differ from the target port.
- TCP MSS clamping on the ingress, configurable (default 1200).
- `--preserve-ip` so the service sees the real client address, using policy routing.
- Detection of subnet conflicts and UDP port conflicts.
- Automatic cleanup of installations from earlier releases (VXLAN and the transitional v2).

## Requirements

- Linux with systemd, and root access.
- Python 3.10 or newer.
- `wireguard-tools`, `nftables`, `openssh-client`, `iproute2` and `procps`.
  On Debian/Ubuntu: `sudo apt install wireguard-tools nftables openssh-client iproute2 procps`
- On the VPS, the WireGuard UDP port (default 51820) open in the provider's firewall.

## Installation

Use a dedicated virtual environment. The launcher written to `/usr/local/bin/pawfwd` runs with that environment's Python, so root must be able to read it.

```bash
sudo python3 -m venv /opt/pawfwd
sudo /opt/pawfwd/bin/pip install git+https://github.com/gabriel-fresan/pawfwd
sudo /opt/pawfwd/bin/pawfwd init --role ingress   # on the VPS
```

## Usage

### 1. Set up the VPS (ingress)

```bash
sudo pawfwd init --role ingress
# optional: --listen-port 51820 --mss 1200
```

The public key printed at the end is used in the next step.

### 2. Connect the home server (target)

```bash
sudo pawfwd init <VPS-PUBLIC-IP> --ssh-host <VPS-SSH-HOST> --name my-server
```

The target registers its own key on the VPS over SSH. If the VPS asks for a password, interactive `sudo` is used in the terminal. For unattended runs, configure an SSH key and a restricted sudo rule.

### 3. Manage forwards (from the target)

```bash
sudo pawfwd add 25505                 # TCP and UDP, same port
sudo pawfwd add 25505:25565/tcp       # public 25505 → target 25565, TCP only
sudo pawfwd add 19132/udp --preserve-ip
sudo pawfwd remove 25505/udp
sudo pawfwd list
sudo pawfwd status
sudo pawfwd diag                      # network, WireGuard and nftables diagnostics
```

Each change is saved to `/etc/paw-fwd/config.json`, applied locally and synchronized to the VPS.

## System names

The project and the command are `pawfwd`. Some system identifiers keep the older `paw-fwd` name so running installations are not broken:

| Resource | Name |
|---|---|
| Command | `pawfwd` |
| Configuration | `/etc/paw-fwd/config.json` |
| WireGuard interface | `paw-fwd` |
| systemd units | `paw-fwd.service`, `wg-quick@paw-fwd.service` |
| nftables tables | `paw_fwd`, `paw_fwd_mss`, `paw_fwd_target` |

Renaming these requires a coordinated migration between the VPS and the home server, and is planned for a future release.

## Nix

The repository includes a flake with the package, the runtime tools on `PATH` and a development shell:

```bash
nix build .#pawfwd          # builds and runs the unit tests
nix develop                 # shell with pytest, ruff and the WireGuard/nftables tools
nix run .#pawfwd -- --help
```

## Security

See [SECURITY.md](SECURITY.md) for the design assumptions and how to report a vulnerability.

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md). The unit tests cover pure functions (parsing, validation, WireGuard configuration, MSS rules, peer registration). Commands that change routing, nftables and systemd need a Linux host with root.

## License

MIT. See [LICENSE](LICENSE).
