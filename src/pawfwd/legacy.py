"""Limpeza de instalações antigas (VXLAN e v2 de transição)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from pawfwd.constants import WG_DIR
from pawfwd.system import run, say


def cleanup_legacy_installation() -> None:
    """Remove only resources created by previous PawFwd releases (VXLAN and transitional WireGuard v2).

    The old JSON config is backed up before removal. Tailscale itself and its
    interfaces/routes are never modified. The legacy policy table is cleaned
    only for rules with the old TCP/UDP source-port selectors and routes that
    explicitly reference paw0 / 10.99.0.0/24.
    """
    legacy_config = Path("/etc/paw-fwd.json")
    if legacy_config.exists():
        backup_dir = Path("/var/backups/paw-fwd")
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / "paw-fwd.json.legacy"
        if not backup.exists():
            shutil.copy2(legacy_config, backup)
            os.chmod(backup, 0o600)
        legacy_config.unlink()
        say(f"[i] Configuração antiga guardada em {backup}.")

    # Stop the old service before replacing its unit with the new one.
    run(["systemctl", "disable", "--now", "paw-fwd.service"], check=False)

    # Clean the short-lived transitional v2 deployment as well. Back up its
    # private config before removing it; the new install uses the canonical
    # paw-fwd names and creates a fresh peer key on the next init.
    transitional_dir = Path("/etc/paw-fwd-v2")
    transitional_wg = WG_DIR / "paw-fwd-v2.conf"
    backup_dir = Path("/var/backups/paw-fwd")
    if transitional_dir.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / "paw-fwd-v2-config.legacy"
        if not backup.exists():
            shutil.copytree(transitional_dir, backup, dirs_exist_ok=True)
            for item in backup.rglob("*"):
                if item.is_file():
                    os.chmod(item, 0o600)
    if transitional_wg.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / "paw-fwd-v2-wireguard.conf.legacy"
        if not backup.exists():
            shutil.copy2(transitional_wg, backup)
            os.chmod(backup, 0o600)
    run(["systemctl", "disable", "--now", "paw-fwd-v2.service"], check=False)
    run(["systemctl", "disable", "--now", "wg-quick@paw-fwd-v2.service"], check=False)
    old_wg_link = run(["ip", "-d", "link", "show", "dev", "paw-fwd-v2"], check=False)
    if old_wg_link.returncode == 0 and "wireguard" in old_wg_link.stdout.lower():
        run(["ip", "link", "delete", "dev", "paw-fwd-v2"], check=False)
    run(["nft", "delete", "table", "ip", "paw_fwd_v2"], check=False)
    run(["nft", "delete", "table", "ip", "paw_fwd_v2_target"], check=False)
    transitional_sysctl = Path("/etc/sysctl.d/99-paw-fwd-v2.conf")
    if transitional_sysctl.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / "99-paw-fwd-v2.conf.legacy"
        if not backup.exists():
            shutil.copy2(transitional_sysctl, backup)
        transitional_sysctl.unlink()
    transitional_dir.exists() and shutil.rmtree(transitional_dir)
    if transitional_wg.exists():
        transitional_wg.unlink()
    transitional_unit = Path("/etc/systemd/system/paw-fwd-v2.service")
    if transitional_unit.exists():
        transitional_unit.unlink()
    run(["systemctl", "daemon-reload"], check=False)

    # Remove only the old v2 mark rules that belong to PawFwd (0x77/0x78).
    listing_v2 = run(["ip", "-4", "rule", "show"], check=False).stdout
    for line in listing_v2.splitlines():
        if "fwmark" not in line:
            continue
        parts = line.replace(":", " ", 1).split()
        if not parts or not parts[0].isdigit():
            continue
        try:
            mark = parts[parts.index("fwmark") + 1]
        except (ValueError, IndexError):
            continue
        if mark not in ("0x77", "0x78", "0x77/0xffffffff", "0x78/0xffffffff"):
            continue
        table = "1999" if ("lookup 1999" in line or "table 1999" in line) else "main"
        run(["ip", "-4", "rule", "del", "pref", parts[0], "fwmark", mark, "table", table], check=False)
    old_routes = run(["ip", "-4", "route", "show", "table", "1999"], check=False).stdout
    for line in old_routes.splitlines():
        if "paw-fwd-v2" not in line and "10.77.0.0/24" not in line and "10.77.0.1" not in line:
            continue
        route = line.split()
        if route:
            run(["ip", "-4", "route", "del", *route, "table", "1999"], check=False)

    # These names are exclusive to the original Tailscale+VXLAN PawFwd.
    run(["nft", "delete", "table", "ip", "paw_port_forward"], check=False)
    run(["nft", "delete", "table", "ip", "paw_port_forward_return"], check=False)

    # Remove only old source-port policy rules that selected table 199.
    listing = run(["ip", "-4", "rule", "show"], check=False).stdout
    for line in listing.splitlines():
        if "lookup 199" not in line and "table 199" not in line:
            continue
        parts = line.replace(":", " ", 1).split()
        if not parts or not parts[0].isdigit() or "ipproto" not in parts or "sport" not in parts:
            continue
        try:
            proto = parts[parts.index("ipproto") + 1]
            sport = parts[parts.index("sport") + 1]
        except (ValueError, IndexError):
            continue
        if proto not in ("tcp", "udp") or not sport.isdigit():
            continue
        while True:
            result = run(["ip", "-4", "rule", "del", "pref", parts[0],
                          "ipproto", proto, "sport", sport, "table", "199"], check=False)
            if result.returncode != 0:
                break

    # Delete only routes that unmistakably belong to the old VXLAN.
    routes = run(["ip", "-4", "route", "show", "table", "199"], check=False).stdout
    for line in routes.splitlines():
        if "paw0" not in line and "10.99.0.0/24" not in line and "10.99.0.1" not in line:
            continue
        route = line.split()
        if route:
            run(["ip", "-4", "route", "del", *route, "table", "199"], check=False)

    # Remove paw0 only when the kernel identifies it as the old VXLAN device.
    link = run(["ip", "-d", "link", "show", "dev", "paw0"], check=False)
    if link.returncode == 0 and "vxlan" in link.stdout.lower() and "id 42" in link.stdout.lower():
        run(["ip", "link", "delete", "dev", "paw0"], check=False)
        say("[i] Interface VXLAN antiga paw0 removida.")

    # Remove the old sysctl drop-in if present; do not reset global or Tailscale
    # runtime sysctls because their previous values are not recoverable safely.
    old_sysctl = Path("/etc/sysctl.d/99-paw-fwd.conf")
    if old_sysctl.exists() and old_sysctl.read_text(errors="ignore").find("tailscale0") >= 0:
        backup = Path("/var/backups/paw-fwd/99-paw-fwd.conf.legacy")
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            shutil.copy2(old_sysctl, backup)
        old_sysctl.unlink()

    say("[+] Limpeza dos recursos antigos concluída; Tailscale foi mantido intacto.")
