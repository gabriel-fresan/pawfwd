# Contributing

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
ruff check . && ruff format --check . && pytest -q
```

## Project layout

- `src/pawfwd/`: the package. Each module has one responsibility (config, network, wireguard, firewall, routing, ssh, ingress, target, rules, reports, install, legacy, cli).
- `tests/`: unit tests for pure functions (port parsing, rule validation, WireGuard config generation, MSS rules, peer registration parsing, launcher generation).

## Guidelines

- Keep parsing and validation as pure functions so they can be unit tested without root.
- Anything that changes the system (`ip`, `nft`, `ufw`, `systemctl`, sysctls, files under `/etc`) belongs in the code paths that already do that, and should be checked on a real Linux host as root.
- Do not rename system identifiers (WireGuard interface, systemd units, `/etc/paw-fwd`, nftables tables) without a migration plan. Existing deployments depend on them.
- Keep the legacy cleanup in `legacy.py` as it is. It exists to remove resources left by earlier releases.
- Use Conventional Commits in the subject line (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `build:`, `style:`).

## Testing on a real host

Unit tests do not exercise routing, nftables or WireGuard. For changes that touch those paths, test on a disposable VPS and a home server, and attach the output of `pawfwd diag` to the pull request.
