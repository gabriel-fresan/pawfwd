"""Configuração e inicialização da interface WireGuard."""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from typing import Any

from pawfwd.constants import WG_CONFIG, WG_DIR, WG_FWMARK, WG_IFACE, WG_MTU
from pawfwd.errors import PawFwdError
from pawfwd.network import address_owner, interface_exists, listen_port_conflicts
from pawfwd.system import atomic_write, run


def start_ingress_wireguard_with_diagnostics(cfg: dict[str, Any]) -> None:
    """Start ingress and distinguish a real address collision from other failures."""
    expected_ip = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)
    try:
        start_wireguard(cfg)
    except PawFwdError as exc:
        owner = address_owner(expected_ip)
        if owner:
            raise PawFwdError(
                f"O endereço {expected_ip} já está atribuído à interface {owner}. "
                "Remova essa atribuição ou escolha uma faixa exclusiva; o PawFwd não vai "
                "trocar de sub-rede às cegas."
            ) from exc
        port = int(cfg["wireguard"]["listen_port"])
        conflicts = listen_port_conflicts(port)
        if conflicts:
            raise PawFwdError(
                f"A porta UDP {port} conflita com outro listener ({'; '.join(conflicts)}). "
                f"Rode 'sudo paw-fwd init --role ingress --listen-port {port + 1}' "
                "e libere essa nova porta UDP no firewall da VPS."
            ) from exc
        raise PawFwdError(
            f"O WireGuard não conseguiu iniciar: {exc}\n"
            "O erro não corresponde a um conflito de sub-rede detectável. "
            "Confira 'sudo wg show all listen-port', 'sudo ss -lunp' e 'sudo journalctl -u wg-quick@paw-fwd -n 50'."
        ) from exc


def serialize_wg_config(cfg: dict[str, Any]) -> str:
    wg = cfg["wireguard"]
    lines = [
        "[Interface]",
        f"PrivateKey = {wg['private_key']}",
        f"Address = {wg['address']}",
        f"MTU = {WG_MTU}",
        "Table = off",
    ]
    if cfg["role"] == "ingress":
        lines.append(f"ListenPort = {wg['listen_port']}")
        for peer in cfg.get("peers", []):
            lines.extend([
                "",
                "[Peer]",
                f"PublicKey = {peer['public_key']}",
                f"AllowedIPs = {peer['tunnel_ip']}/32",
            ])
    else:
        peer = cfg["ingress_peer"]
        lines.extend([
            f"FwMark = {WG_FWMARK}",
            "",
            "[Peer]",
            f"PublicKey = {peer['public_key']}",
            f"Endpoint = {peer['endpoint']}:{peer['listen_port']}",
            # This permits return packets to arbitrary client IPs, but Table=off
            # prevents WireGuard from replacing the host's normal default route.
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = 25",
        ])
    return "\n".join(lines) + "\n"


def write_wg_config(cfg: dict[str, Any]) -> None:
    atomic_write(WG_CONFIG, serialize_wg_config(cfg), 0o600)


def start_wireguard(cfg: dict[str, Any]) -> None:
    WG_DIR.mkdir(parents=True, exist_ok=True)
    write_wg_config(cfg)
    expected_ip = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)
    must_restart = False
    if interface_exists():
        current = run(["ip", "-j", "-4", "addr", "show", "dev", WG_IFACE], check=False)
        try:
            current_items = json.loads(current.stdout or "[]")
            assigned = {
                info.get("local")
                for item in current_items
                for info in item.get("addr_info", [])
                if info.get("family") == "inet"
            }
        except json.JSONDecodeError:
            assigned = set()
        must_restart = expected_ip not in assigned

    if not interface_exists() or must_restart:
        if must_restart:
            run(["systemctl", "stop", f"wg-quick@{WG_IFACE}.service"], check=False)
            run(["wg-quick", "down", WG_IFACE], check=False)
        result = run(["systemctl", "start", f"wg-quick@{WG_IFACE}.service"], check=False)
        if result.returncode != 0:
            run(["wg-quick", "up", WG_IFACE])
    else:
        # Apply an updated peer list without bouncing a correctly addressed interface.
        stripped = run(["wg-quick", "strip", WG_IFACE]).stdout
        fd, temp_name = tempfile.mkstemp(prefix="paw-fwd-wg-", dir="/run")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(stripped)
            os.chmod(temp_name, 0o600)
            run(["wg", "syncconf", WG_IFACE, temp_name])
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
    if cfg["role"] == "ingress":
        for peer in cfg.get("peers", []):
            run(["ip", "-4", "route", "replace", f"{peer['tunnel_ip']}/32", "dev", WG_IFACE])
    else:
        run(["ip", "-4", "route", "replace", f"{cfg['ingress_peer']['tunnel_ip']}/32", "dev", WG_IFACE])
