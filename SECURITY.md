# Security

## Reporting

Please use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability"). Do not open a public issue for security bugs.

## Design assumptions

- `pawfwd` runs as **root**. It writes WireGuard configuration, manages nftables, ufw, sysctls and systemd units.
- The WireGuard private key and `/etc/paw-fwd/config.json` are written with mode `0600`.
- The VPS (ingress) sees the public traffic of every forwarded port and the IP of the home server's WireGuard peer. Only forward ports you intend to publish.
- SSH is used only for peer enrollment and rule synchronization. The first connection accepts the host key (`StrictHostKeyChecking=accept-new`), so verify the VPS fingerprint on first `init`. Prefer key-based authentication.
- Rule synchronization runs `sudo -n pawfwd rules import` on the VPS. Grant that sudo rule only for the `pawfwd` binary, not for a general shell.
- The VPS accepts rules only for peers already registered with `pawfwd peer register`, and validates port numbers and protocols before applying them.
- Tailscale is never reconfigured by pawfwd. The legacy cleanup removes only resources created by earlier PawFwd releases (VXLAN `paw0`, the transitional v2 interface and tables), and backs up configuration files before deleting them.
- Pin the WireGuard, nftables and OpenSSH versions your distribution ships, and keep the VPS firewall in sync with the UDP port pawfwd opens.
