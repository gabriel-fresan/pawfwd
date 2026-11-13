"""Descoberta de redes locais, portas UDP e sub-redes do túnel."""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from typing import Any

from pawfwd.constants import TUNNEL_NETWORK_CANDIDATES, WG_IFACE, WG_PORT_DEFAULT
from pawfwd.errors import PawFwdError
from pawfwd.system import run, say


def host_networks_on_machine() -> list[ipaddress.IPv4Network]:
    """Read local IPv4 interface prefixes and main-table routes to avoid subnet clashes."""
    networks: list[ipaddress.IPv4Network] = []
    addr_result = run(["ip", "-j", "-4", "addr", "show"], check=False)
    if addr_result.returncode == 0 and addr_result.stdout.strip():
        try:
            items = json.loads(addr_result.stdout)
        except json.JSONDecodeError:
            items = []
        for item in items:
            if item.get("ifname") == WG_IFACE:
                continue
            for info in item.get("addr_info", []):
                if info.get("family") != "inet":
                    continue
                try:
                    iface = ipaddress.IPv4Interface(f"{info['local']}/{info['prefixlen']}")
                    networks.append(iface.network)
                except (KeyError, ValueError):
                    pass

    routes = run(["ip", "-4", "route", "show", "table", "main"], check=False)
    for line in routes.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        destination = fields[0]
        if destination in ("default", "broadcast", "local", "throw", "unreachable", "prohibit", "blackhole"):
            continue
        # Ignore the connected prefix installed by our own active interface.
        if "dev" in fields and fields[fields.index("dev") + 1] == WG_IFACE:
            continue
        try:
            networks.append(ipaddress.IPv4Network(destination, strict=False))
        except ValueError:
            continue
    return networks


def choose_tunnel_network(preferred: str | None = None, excluded: set[str] | None = None) -> str:
    """Choose a private /24 that does not overlap host interfaces or main routes."""
    used = host_networks_on_machine()
    excluded = {str(ipaddress.IPv4Network(item, strict=False)) for item in (excluded or set())}
    candidates = [item for item in TUNNEL_NETWORK_CANDIDATES if item not in excluded]
    if preferred:
        preferred = str(ipaddress.IPv4Network(preferred, strict=False))
        candidates = ([preferred] if preferred not in excluded else []) + [
            candidate for candidate in candidates if candidate != preferred
        ]
    for candidate in candidates:
        network = ipaddress.IPv4Network(candidate)
        if not any(network.overlaps(existing) for existing in used):
            return str(network)
    details = ", ".join(str(net) for net in sorted(set(used), key=lambda n: (int(n.network_address), n.prefixlen)))
    raise PawFwdError(
        "Não encontrei uma sub-rede /24 livre para o túnel PawFwd. "
        f"Redes locais/rotas detectadas: {details or 'não foi possível detectar'}. "
        "Ajuste as redes da máquina ou defina uma faixa exclusiva antes de inicializar."
    )


def wireguard_listen_ports() -> dict[int, list[str]]:
    """Return UDP listen ports owned by existing WireGuard interfaces."""
    interfaces = run(["wg", "show", "interfaces"], check=False).stdout.split()
    result: dict[int, list[str]] = {}
    for interface in interfaces:
        port_result = run(["wg", "show", interface, "listen-port"], check=False)
        if port_result.returncode != 0:
            continue
        try:
            port = int(port_result.stdout.strip())
        except ValueError:
            continue
        if port:
            result.setdefault(port, []).append(interface)
    return result


def udp_socket_listeners() -> dict[int, list[str]]:
    """Read local UDP listeners with ss; values are short diagnostic descriptions."""
    if shutil.which("ss") is None:
        return {}
    result = run(["ss", "-H", "-lunp"], check=False)
    listeners: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        match = re.search(r":(\d+)$", fields[3])
        if not match:
            continue
        port = int(match.group(1))
        listeners.setdefault(port, []).append(line.strip())
    return listeners


def listen_port_conflicts(port: int) -> list[str]:
    """Identify listeners that would prevent PawFwd from binding its UDP port."""
    wg_ports = wireguard_listen_ports()
    owners = [name for name in wg_ports.get(port, []) if name != WG_IFACE]
    socket_lines = udp_socket_listeners().get(port, [])
    paw_fwd_is_owner = WG_IFACE in wg_ports.get(port, [])
    if paw_fwd_is_owner and not owners:
        # An already-running PawFwd interface is the expected owner during re-init.
        return []
    details = [f"WireGuard {name}" for name in owners]
    if socket_lines and not paw_fwd_is_owner:
        details.extend(socket_lines)
    return list(dict.fromkeys(details))


def select_listen_port(requested: int | None, existing: dict[str, Any] | None) -> int:
    """Preserve an existing port or pick a free one; never silently override explicit input."""
    preferred = requested
    if preferred is None:
        preferred = int((existing or {}).get("wireguard", {}).get("listen_port", WG_PORT_DEFAULT))
    if not 1 <= int(preferred) <= 65535:
        raise PawFwdError("A porta UDP do WireGuard precisa estar entre 1 e 65535.")

    conflicts = listen_port_conflicts(int(preferred))
    if not conflicts:
        return int(preferred)
    if requested is not None:
        raise PawFwdError(
            f"A porta UDP {preferred} já está em uso ({'; '.join(conflicts)}). "
            "Escolha outra com --listen-port. Isso não é conflito de sub-rede."
        )

    # Automatic mode: preserve the previous/default port when possible, otherwise
    # find a nearby free UDP port and make the chosen value explicit in the output.
    candidates = [p for p in range(int(preferred) + 1, min(65536, int(preferred) + 33))]
    for candidate in candidates:
        if not listen_port_conflicts(candidate):
            say(f"[!] UDP {preferred} já está ocupada ({'; '.join(conflicts)}).")
            say(f"[i] PawFwd usará UDP {candidate}; libere essa porta no firewall da VPS.")
            return candidate
    raise PawFwdError(
        f"Não encontrei uma porta UDP livre próxima de {preferred}. "
        "Use 'sudo wg show all listen-port' e 'sudo ss -lunp' para inspecionar os listeners, "
        "ou escolha --listen-port manualmente."
    )


def address_owner(address: str) -> str | None:
    """Return another interface holding this exact IPv4 address, if any."""
    result = run(["ip", "-j", "-4", "addr", "show"], check=False)
    try:
        items = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    for item in items:
        if item.get("ifname") == WG_IFACE:
            continue
        for info in item.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local") == address:
                return str(item.get("ifname", "outra interface"))
    return None


def interface_exists() -> bool:
    return run(["ip", "link", "show", "dev", WG_IFACE], check=False).returncode == 0


def public_interface() -> str | None:
    result = run(["ip", "-4", "route", "get", "1.1.1.1"], check=False)
    match = re.search(r"\bdev\s+(\S+)", result.stdout)
    return match.group(1) if match else None
