#!/usr/bin/env python3
"""PawFwd - kernel-space port forwarding over a dedicated WireGuard tunnel.

The Tailscale installation is deliberately left untouched. SSH is used only
for initial peer enrollment and forwarding-rule synchronization.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import ipaddress
import json
import os
import pty
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

VERSION = "2.2.0"
CONFIG_DIR = Path("/etc/paw-fwd")
CONFIG_PATH = CONFIG_DIR / "config.json"
WG_DIR = Path("/etc/wireguard")
WG_CONFIG = WG_DIR / "paw-fwd.conf"
WG_IFACE = "paw-fwd"
WG_PORT_DEFAULT = 51820
INGRESS_TUNNEL_IP = "10.77.0.1"
TUNNEL_NETWORK = "10.77.0.0/24"
TUNNEL_NETWORK_CANDIDATES = [
    "10.77.0.0/24", "10.78.0.0/24", "10.79.0.0/24",
    "10.90.0.0/24", "10.250.0.0/24", "172.31.240.0/24",
    "192.168.254.0/24", "192.168.253.0/24",
]
WG_MTU = 1420
RT_TABLE_ID = "1999"
WG_FWMARK = "0x77"  # WireGuard outer UDP packets: keep using the normal host route.
RETURN_FWMARK = "0x78"  # Conntrack-marked replies: send back through PawFwd.
WG_MARK_RULE_BASE = 11000
RULE_PRIORITY_BASE = 12000
RULE_PRIORITY_MAX = 30000
NFT_TABLE = "paw_fwd"
MSS_NFT_TABLE = "paw_fwd_mss"
MSS_PROBE_NFT_TABLE = "pawfwd_mss_probe"
TCP_MSS_DEFAULT = 1200
TCP_MSS_MIN = 536
TCP_MSS_MAX = WG_MTU - 40
TARGET_NFT_TABLE = "paw_fwd_target"
INSTALL_PATH = Path("/usr/local/bin/paw-fwd")
SYSTEMD_UNIT = Path("/etc/systemd/system/paw-fwd.service")
SYSCTL_FILE = Path("/etc/sysctl.d/99-paw-fwd.conf")


class PawFwdError(RuntimeError):
    pass


def say(message: str = "") -> None:
    print(message)


def run(command: list[str], *, input_text: str | None = None,
        check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=capture,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PawFwdError(f"Comando não encontrado: {command[0]}. Instale as dependências do PawFwd.") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "sem detalhes").strip()
        raise PawFwdError(f"Falha ao executar {' '.join(command)}: {detail}")
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise PawFwdError("Preciso de privilégios de administrador. Rode com sudo.")


def ensure_dependencies() -> None:
    required = ["ip", "wg", "wg-quick", "systemctl", "ssh", "sysctl", "nft"]
    missing = [item for item in required if shutil.which(item) is None]
    if missing:
        raise PawFwdError(
            "Dependências ausentes: " + ", ".join(missing) +
            ". No Debian/Ubuntu: sudo apt install wireguard-tools nftables openssh-client iproute2 procps"
        )


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def load_config(required: bool = True) -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        if required:
            raise PawFwdError("PawFwd ainda não foi inicializado. Comece com 'paw-fwd init'.")
        return {}
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PawFwdError(f"Não consegui ler {CONFIG_PATH}: {exc}") from exc
    if cfg.get("schema_version") != 2:
        raise PawFwdError(
            "Esta configuração não é da versão 2. A configuração antiga foi preservada; "
            "faça backup antes de migrar."
        )
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    atomic_write(CONFIG_PATH, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", 0o600)


def genkey() -> tuple[str, str]:
    private = run(["wg", "genkey"]).stdout.strip()
    pub = run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
    if not private or not pub:
        raise PawFwdError("O WireGuard não conseguiu gerar um par de chaves.")
    return private, pub


def validate_port(value: Any, label: str = "porta") -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise PawFwdError(f"{label.capitalize()} inválida: {value!r}.") from exc
    if not 1 <= port <= 65535:
        raise PawFwdError(f"{label.capitalize()} precisa estar entre 1 e 65535.")
    return port


def parse_port_spec(spec: str) -> dict[str, Any]:
    """Parse <public>[:<target>][/<tcp|udp>], defaulting to both protocols."""
    match = re.fullmatch(r"(?P<public>\d+)(?::(?P<target>\d+))?(?:/(?P<proto>tcp|udp))?", spec.strip().lower())
    if not match:
        raise PawFwdError(
            f"Formato inválido: {spec!r}. Use PORTA, PORTA:DESTINO, PORTA/tcp ou PORTA:DESTINO/udp."
        )
    public = validate_port(match.group("public"), "porta pública")
    target = validate_port(match.group("target") or public, "porta de destino")
    proto = match.group("proto") or "both"
    return {
        "public_port": public,
        "target_port": target,
        "protocols": ["tcp", "udp"] if proto == "both" else [proto],
    }


def validate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    public_port = validate_port(rule.get("public_port"), "porta pública")
    target_port = validate_port(rule.get("target_port", public_port), "porta de destino")
    proto = rule.get("proto")
    if proto not in ("tcp", "udp"):
        raise PawFwdError(f"Protocolo interno inválido na regra {public_port}: {proto!r}.")
    preserve = bool(rule.get("preserve_ip", False))
    peer_ip = str(ipaddress.IPv4Address(rule.get("peer_ip", "0.0.0.0")))
    return {
        "public_port": public_port,
        "target_port": target_port,
        "proto": proto,
        "preserve_ip": preserve,
        "peer_ip": peer_ip,
    }


def expand_stored_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for rule in rules:
        proto = rule.get("proto", "both")
        protocols = ["tcp", "udp"] if proto == "both" else [proto]
        if any(p not in ("tcp", "udp") for p in protocols):
            raise PawFwdError(f"Protocolo inválido na regra: {proto!r}.")
        for p in protocols:
            item = dict(rule)
            item["proto"] = p
            result.append(validate_rule(item))
    # Keep exactly one rule for each public-port/protocol pair.
    unique: dict[tuple[int, str], dict[str, Any]] = {}
    for item in result:
        unique[(item["public_port"], item["proto"])] = item
    return list(unique.values())


def tunnel_details(cfg: dict[str, Any]) -> tuple[str, str]:
    """Return the configured tunnel network and ingress address, including old configs."""
    if cfg.get("tunnel_network"):
        network = str(ipaddress.IPv4Network(cfg["tunnel_network"], strict=False))
    elif cfg.get("role") == "ingress":
        network = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).network)
    else:
        network = str(ipaddress.IPv4Network(
            cfg.get("ingress_peer", {}).get("tunnel_network", TUNNEL_NETWORK), strict=False
        ))
    if cfg.get("ingress_tunnel_ip"):
        ingress_ip = str(ipaddress.IPv4Address(cfg["ingress_tunnel_ip"]))
    elif cfg.get("role") == "ingress":
        ingress_ip = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)
    else:
        ingress_ip = str(ipaddress.IPv4Address(
            cfg.get("ingress_peer", {}).get("tunnel_ip", INGRESS_TUNNEL_IP)
        ))
    return network, ingress_ip


def _host_networks_on_machine() -> list[ipaddress.IPv4Network]:
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
    used = _host_networks_on_machine()
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


def interface_exists() -> bool:
    return run(["ip", "link", "show", "dev", WG_IFACE], check=False).returncode == 0


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


def install_self() -> None:
    source = Path(__file__).resolve()
    INSTALL_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        if source != INSTALL_PATH.resolve():
            shutil.copy2(source, INSTALL_PATH)
        os.chmod(INSTALL_PATH, 0o755)
    except OSError as exc:
        raise PawFwdError(f"Não consegui instalar o executável em {INSTALL_PATH}: {exc}") from exc


def install_systemd() -> None:
    unit = f"""[Unit]
Description=PawFwd port forwarding rules
Documentation=man:wg-quick(8)
After=network-online.target wg-quick@paw-fwd.service
Wants=network-online.target
Requires=wg-quick@paw-fwd.service

[Service]
Type=oneshot
ExecStart={INSTALL_PATH} apply
ExecReload={INSTALL_PATH} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    atomic_write(SYSTEMD_UNIT, unit, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "wg-quick@paw-fwd.service", "paw-fwd.service"])


def persist_sysctls() -> None:
    # Do not change Tailscale's sysctls or the host-wide rp_filter policy.
    # The tunnel interface gets loose reverse-path filtering at apply time.
    content = "net.ipv4.ip_forward=1\n"
    atomic_write(SYSCTL_FILE, content, 0o644)
    run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
    run(["sysctl", "-q", "-w", f"net.ipv4.conf.{WG_IFACE}.rp_filter=2"])


def open_wireguard_firewall(port: int) -> None:
    """Open WireGuard in common host firewalls; cloud firewalls remain external."""
    ufw = shutil.which("ufw")
    if ufw:
        status = run([ufw, "status"], check=False)
        if "Status: active" in status.stdout:
            run([ufw, "allow", f"{port}/udp", "comment", "PawFwd WireGuard"], check=False)
            say(f"[i] UFW: regra UDP {port} solicitada.")
            return
    firewalld = shutil.which("firewall-cmd")
    if firewalld:
        state = run([firewalld, "--state"], check=False)
        if state.returncode == 0 and state.stdout.strip() == "running":
            run([firewalld, "--permanent", f"--add-port={port}/udp"])
            run([firewalld, "--reload"])
            say(f"[i] firewalld: UDP {port} liberado.")
            return
    say(f"[!] Confira o firewall do provedor e libere UDP {port} na VPS.")


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


def assign_ingress_network(cfg: dict[str, Any], network: str) -> None:
    """Move ingress and its registered peer(s) to another unused tunnel subnet."""
    network_obj = ipaddress.IPv4Network(network, strict=False)
    hosts = iter(network_obj.hosts())
    ingress_ip = str(next(hosts))
    new_peer_ips: dict[str, str] = {}
    for peer in cfg.get("peers", []):
        new_ip = str(next(hosts))
        new_peer_ips[peer["tunnel_ip"]] = new_ip
        peer["tunnel_ip"] = new_ip
    cfg["tunnel_network"] = str(network_obj)
    cfg["ingress_tunnel_ip"] = ingress_ip
    cfg["wireguard"]["address"] = f"{ingress_ip}/{network_obj.prefixlen}"
    for rule in cfg.get("rules", []):
        old_ip = rule.get("peer_ip")
        if old_ip in new_peer_ips:
            rule["peer_ip"] = new_peer_ips[old_ip]


def init_ingress(requested_listen_port: int | None, requested_mss: int | None = None) -> None:
    ensure_dependencies()
    cleanup_legacy_installation()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_config(required=False)
    if existing and existing.get("role") != "ingress":
        raise PawFwdError("Esta máquina já foi inicializada como target. Não vou trocar o papel automaticamente.")

    if existing:
        cfg = existing
        old_network, old_ingress_ip = tunnel_details(cfg)
        say("[*] Configuração de ingress existente; preservando as chaves e peers.")
    else:
        private, public = genkey()
        old_network, old_ingress_ip = TUNNEL_NETWORK, INGRESS_TUNNEL_IP
        cfg = {
            "schema_version": 2,
            "role": "ingress",
            "wireguard": {
                "private_key": private,
                "public_key": public,
                "address": f"{INGRESS_TUNNEL_IP}/24",
                "listen_port": WG_PORT_DEFAULT,
            },
            "tunnel_network": TUNNEL_NETWORK,
            "ingress_tunnel_ip": INGRESS_TUNNEL_IP,
            "peers": [],
            "rules": [],
        }

    listen_port = select_listen_port(requested_listen_port, cfg if existing else None)
    cfg["wireguard"]["listen_port"] = listen_port
    cfg["tcp_mss"] = validate_tcp_mss(requested_mss if requested_mss is not None else cfg.get("tcp_mss", TCP_MSS_DEFAULT))
    selected_network = choose_tunnel_network(old_network)
    network_obj = ipaddress.IPv4Network(selected_network)
    if selected_network != old_network:
        say(f"[!] A sub-rede {old_network} conflita com uma rede/rota desta máquina.")
        say(f"[i] Usando a sub-rede livre {selected_network} para o túnel.")
        assign_ingress_network(cfg, selected_network)
        # If a previous partial init left the interface active, bring it down
        # before changing its address and AllowedIPs.
        run(["systemctl", "stop", f"wg-quick@{WG_IFACE}.service"], check=False)
        if interface_exists():
            run(["ip", "link", "delete", "dev", WG_IFACE], check=False)
    else:
        cfg["tunnel_network"] = selected_network
        cfg["ingress_tunnel_ip"] = old_ingress_ip
        cfg["wireguard"]["address"] = f"{old_ingress_ip}/{network_obj.prefixlen}"

    save_config(cfg)
    install_self()
    install_systemd()
    start_ingress_wireguard_with_diagnostics(cfg)
    persist_sysctls()
    open_wireguard_firewall(listen_port)
    run(["systemctl", "restart", "paw-fwd.service"])
    say("\n< PawFwd ingress pronto! >")
    say(f"  Interface : {WG_IFACE} ({cfg['ingress_tunnel_ip']})")
    say(f"  Sub-rede  : {cfg['tunnel_network']}")
    say(f"  WireGuard : UDP {listen_port} · MTU {WG_MTU}")
    say(f"  TCP MSS   : clamp até {cfg['tcp_mss']} bytes")
    say(f"  Chave pub.: {cfg['wireguard']['public_key']}")
    say("  Próximo   : no servidor doméstico, rode:")
    say("              sudo paw-fwd init <IP-PUBLICO> --ssh-host <HOST-SSH>\n")


def _interactive_ssh(command: list[str]) -> tuple[int, str]:
    """Run SSH attached to a local PTY so SSH and remote sudo can prompt normally."""
    transcript = bytearray()

    def read_and_forward(fd: int) -> bytes:
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if data:
            transcript.extend(data)
        # pty.spawn writes the bytes returned by master_read to our stdout.
        # Writing them here as well duplicated sudo prompts and JSON output.
        return data

    status = pty.spawn(command, master_read=read_and_forward)
    exit_code = os.waitstatus_to_exitcode(status)
    return exit_code, transcript.decode("utf-8", errors="replace")


def ssh_remote(host: str, user: str, port: int, remote_command: list[str]) -> str:
    """Try key/non-interactive SSH first, then fall back to an interactive SSH+sudo session.

    The interactive fallback is intentionally available only from a terminal. It
    does not store passwords or weaken sudoers; remote sudo prompts the user as usual.
    """
    ssh_target = f"{user}@{host}" if user else host
    remote_text = " ".join(shlex.quote(part) for part in remote_command)

    def make_ssh(*, interactive: bool) -> list[str]:
        command = ["ssh"]
        if interactive:
            command.append("-tt")
        command.extend([
            "-p", str(port),
            "-o", f"BatchMode={'no' if interactive else 'yes'}",
            "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new",
            ssh_target, remote_text,
        ])
        # Use the invoking user's SSH keys and known_hosts, not root's files.
        local_user = os.environ.get("SUDO_USER")
        if local_user and local_user != "root":
            command = ["sudo", "-H", "-u", local_user, *command]
        return command

    result = run(make_ssh(interactive=False), check=False)
    if result.returncode == 0:
        return result.stdout.strip()

    details = (result.stderr or result.stdout or "sem detalhes").strip()
    if sys.stdin.isatty() and sys.stdout.isatty():
        say("\n[*] A VPS precisa de autenticação adicional. Abrindo SSH interativo...")
        interactive_command = list(remote_command)
        # The normal path uses sudo -n so automation never hangs. In this
        # terminal-only fallback, remove -n and let sudo display its password prompt.
        if len(interactive_command) >= 2 and interactive_command[:2] == ["sudo", "-n"]:
            interactive_command = ["sudo", *interactive_command[2:]]
        remote_text = " ".join(shlex.quote(part) for part in interactive_command)
        interactive_status, transcript = _interactive_ssh(make_ssh(interactive=True))
        if interactive_status == 0:
            return transcript.strip()
        details = transcript.strip() or details

    raise PawFwdError(
        f"Não consegui executar o comando na VPS ({ssh_target}): {details}\n"
        "Em um terminal, o PawFwd permite autenticação SSH e senha sudo interativas. "
        "Sem terminal (por exemplo, em um serviço), configure uma chave SSH e "
        "permissão sudo restrita para os comandos do PawFwd, ou use --ssh-user root."
    )


def parse_peer_registration(output: str) -> dict[str, Any]:
    """Extract the peer JSON even when an interactive PTY appends SSH messages."""
    required = {"target_tunnel_ip", "ingress_tunnel_ip", "ingress_public_key", "listen_port"}
    candidates = output.replace("\r", "\n").splitlines()
    for line in reversed(candidates):
        candidate = line.strip()
        if not candidate.startswith("{") or not candidate.endswith("}"):
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and required.issubset(value):
            # Validate values before mutating the target config.
            ipaddress.IPv4Address(value["target_tunnel_ip"])
            ipaddress.IPv4Address(value["ingress_tunnel_ip"])
            ipaddress.IPv4Network(value.get("tunnel_network", TUNNEL_NETWORK), strict=False)
            base64.b64decode(value["ingress_public_key"], validate=True)
            int(value["listen_port"])
            return value
    tail = "\n".join(candidates[-12:])[-1200:]
    raise PawFwdError(
        "A VPS não retornou um registro de pareamento válido. "
        f"Saída recebida:\n{tail or '(vazia)'}. "
        "O cadastro pode ter sido criado na VPS; execute init novamente para repetir com a mesma chave."
    )


def init_target(endpoint: str, ssh_host: str | None, ssh_user: str | None,
                ssh_port: int, name: str | None) -> None:
    ensure_dependencies()
    cleanup_legacy_installation()
    try:
        endpoint_host = str(ipaddress.IPv4Address(endpoint))
    except ipaddress.AddressValueError:
        # Hostnames are allowed for dynamic DNS endpoints.
        if not re.fullmatch(r"[A-Za-z0-9.-]+", endpoint) or endpoint.startswith("-"):
            raise PawFwdError("Endpoint inválido. Informe um IPv4 público ou hostname DNS.")
        endpoint_host = endpoint
    if not name:
        name = socket.gethostname()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise PawFwdError("Nome do peer inválido. Use letras, números, ponto, hífen ou underscore.")

    current = load_config(required=False)
    if current:
        if current.get("role") != "target":
            raise PawFwdError("Esta máquina já foi inicializada como ingress. Faça backup antes de trocar o papel.")
        known_endpoint = current.get("ingress_peer", {}).get("endpoint") or current.get("pending_endpoint")
        if known_endpoint and known_endpoint != endpoint_host:
            raise PawFwdError("Esta máquina já está vinculada a outro endpoint. Faça backup antes de reinicializar.")
        cfg = current
        public_key = cfg["wireguard"]["public_key"]
        say("[*] Configuração target existente; reutilizando a chave WireGuard.")
    else:
        private, public_key = genkey()
        cfg = {
            "schema_version": 2,
            "role": "target",
            "wireguard": {
                "private_key": private,
                "public_key": public_key,
                "address": "10.77.0.2/32",
            },
            "rules": [],
        }

    user = ssh_user or os.environ.get("SUDO_USER") or getpass.getuser()
    control_host = ssh_host or endpoint_host
    if not 1 <= ssh_port <= 65535:
        raise PawFwdError("A porta SSH precisa estar entre 1 e 65535.")
    cfg["pending_endpoint"] = endpoint_host
    cfg["peer_name"] = name
    cfg["control"] = {"host": control_host, "user": user, "port": ssh_port}
    save_config(cfg)  # Preserve the generated key so a failed SSH retry is idempotent.
    say(f"[*] Registrando este servidor na VPS via SSH ({user}@{control_host})...")
    remote_output = ssh_remote(
        control_host, user, ssh_port,
        ["sudo", "-n", str(INSTALL_PATH), "peer", "register",
         "--public-key", public_key, "--name", name],
    )
    registration = parse_peer_registration(remote_output)

    cfg.pop("pending_endpoint", None)
    cfg["ingress_peer"] = {
        "public_key": registration["ingress_public_key"],
        "endpoint": endpoint_host,
        "listen_port": int(registration["listen_port"]),
        "tunnel_ip": registration["ingress_tunnel_ip"],
        "tunnel_network": registration.get("tunnel_network", TUNNEL_NETWORK),
    }
    cfg["wireguard"]["address"] = f"{registration['target_tunnel_ip']}/32"
    save_config(cfg)
    install_self()
    install_systemd()
    start_wireguard(cfg)
    persist_sysctls()
    run(["systemctl", "start", "paw-fwd.service"])
    say("\n< PawFwd target conectado! >")
    say(f"  Peer      : {name}")
    say(f"  Túnel     : {cfg['wireguard']['address']} → {registration['ingress_tunnel_ip']}")
    say("  Tailscale : continua intocado; ele ainda pode cuidar do SSH e da administração.")
    say("\nAgora você já pode usar 'sudo paw-fwd add 25505'. :3\n")


def peer_register(public_key: str, name: str) -> None:
    cfg = load_config()
    if cfg.get("role") != "ingress":
        raise PawFwdError("O cadastro de peers só pode ser executado no ingress.")
    try:
        decoded = base64.b64decode(public_key, validate=True)
    except Exception as exc:
        raise PawFwdError("Chave pública WireGuard inválida.") from exc
    if len(decoded) != 32:
        raise PawFwdError("A chave pública WireGuard precisa ter 32 bytes.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        raise PawFwdError("Nome do peer inválido.")

    peers = cfg.setdefault("peers", [])
    existing = next((p for p in peers if p["name"] == name), None)
    network, ingress_ip = tunnel_details(cfg)
    network_obj = ipaddress.IPv4Network(network)
    if existing and existing["public_key"] != public_key:
        raise PawFwdError(f"Já existe um peer chamado {name!r} com outra chave. Remova-o primeiro.")
    if peers and not existing:
        raise PawFwdError("Esta versão suporta um target por ingress. O suporte multi-target fica para uma próxima versão.")
    if existing:
        peer = existing
        if ipaddress.IPv4Address(peer["tunnel_ip"]) not in network_obj or peer["tunnel_ip"] == ingress_ip:
            old_ip = peer["tunnel_ip"]
            peer["tunnel_ip"] = str(next(ip for ip in network_obj.hosts() if str(ip) != ingress_ip))
            run(["ip", "-4", "route", "del", f"{old_ip}/32", "dev", WG_IFACE], check=False)
    else:
        host_ip = next((str(ip) for ip in network_obj.hosts() if str(ip) != ingress_ip), None)
        if not host_ip:
            raise PawFwdError("A rede do túnel está cheia (máximo de 253 peers).")
        peer = {"name": name, "public_key": public_key, "tunnel_ip": host_ip}
        peers.append(peer)

    save_config(cfg)
    if interface_exists():
        run(["wg", "set", WG_IFACE, "peer", public_key, "allowed-ips", f"{peer['tunnel_ip']}/32"])
        run(["ip", "-4", "route", "replace", f"{peer['tunnel_ip']}/32", "dev", WG_IFACE])
    write_wg_config(cfg)
    response = {
        "peer_name": name,
        "target_tunnel_ip": peer["tunnel_ip"],
        "ingress_tunnel_ip": ingress_ip,
        "tunnel_network": network,
        "ingress_public_key": cfg["wireguard"]["public_key"],
        "listen_port": cfg["wireguard"]["listen_port"],
        "tcp_mss": cfg.get("tcp_mss", TCP_MSS_DEFAULT),
    }
    print(json.dumps(response))


def ufw_active() -> bool:
    if not shutil.which("ufw"):
        return False
    result = run(["ufw", "status"], check=False)
    return "Status: active" in result.stdout


def public_interface() -> str | None:
    result = run(["ip", "-4", "route", "get", "1.1.1.1"], check=False)
    match = re.search(r"\bdev\s+(\S+)", result.stdout)
    return match.group(1) if match else None


def rebuild_ufw_rules(cfg: dict[str, Any], rules: list[dict[str, Any]], wan: str | None = None) -> None:
    if not ufw_active():
        return
    # Delete only rules carrying our explicit comment; leave the user's firewall alone.
    listing = run(["ufw", "status", "numbered"], check=False).stdout
    numbers = []
    for line in listing.splitlines():
        if "PawFwd" in line:
            match = re.match(r"\[\s*(\d+)\]", line)
            if match:
                numbers.append(int(match.group(1)))
    for number in sorted(numbers, reverse=True):
        run(["ufw", "--force", "delete", str(number)], check=False)

    listen_port = int(cfg["wireguard"]["listen_port"])
    run(["ufw", "allow", f"{listen_port}/udp", "comment", "PawFwd WireGuard"], check=False)
    if not rules:
        return
    if not wan:
        say("[!] UFW ativo, mas não consegui detectar a interface pública; confira as regras de encaminhamento.")
        return
    for rule in rules:
        proto = rule["proto"]
        run(["ufw", "route", "allow", "in", "on", wan, "out", "on", WG_IFACE,
             "to", rule["peer_ip"], "port", str(rule["target_port"]), "proto", proto,
             "comment", "PawFwd"], check=False)


def validate_tcp_mss(value: Any) -> int:
    """Validate the TCP MSS ceiling used on forwarded SYN/SYN-ACK packets."""
    try:
        mss = int(value)
    except (TypeError, ValueError) as exc:
        raise PawFwdError(f"MSS TCP inválido: {value!r}.") from exc
    if not TCP_MSS_MIN <= mss <= TCP_MSS_MAX:
        raise PawFwdError(
            f"MSS TCP precisa estar entre {TCP_MSS_MIN} e {TCP_MSS_MAX} "
            f"para MTU {WG_MTU}."
        )
    return mss


def build_mss_ruleset(cfg: dict[str, Any], rules: list[dict[str, Any]], wan: str) -> str | None:
    """Build MSS clamps at ingress VPS PREROUTING for both directions.

    The incoming client SYN is seen on the WAN before DNAT, so it matches the
    public port. The returning server SYN-ACK enters from WireGuard and still
    has the target host port as its source port, so it matches target_port.
    A conservative default of 1200 is based on the verified Minecraft path;
    it is intentionally not inferred from WireGuard MTU alone because the
    underlay/Internet path can have a smaller effective PMTU.
    """
    tcp_rules = [r for r in rules if r["proto"] == "tcp"]
    if not tcp_rules:
        return None
    mss = validate_tcp_mss(cfg.get("tcp_mss", TCP_MSS_DEFAULT))
    seen: set[tuple[str, int, str, int]] = set()
    statements: list[str] = []
    for rule in tcp_rules:
        key = (rule["peer_ip"], rule["public_port"], WG_IFACE, rule["target_port"])
        if key in seen:
            continue
        seen.add(key)
        peer_ip, public_port, _, target_port = key
        statements.append(
            f'iifname "{wan}" tcp dport {public_port} '
            f'tcp flags & (syn | ack) == syn '
            f'tcp option maxseg size > {mss} '
            f'tcp option maxseg size set {mss} counter'
        )
        statements.append(
            f'iifname "{WG_IFACE}" ip saddr {peer_ip} tcp sport {target_port} '
            f'tcp flags & (syn | ack) == (syn | ack) '
            f'tcp option maxseg size > {mss} '
            f'tcp option maxseg size set {mss} counter'
        )
    return f"""
table inet {MSS_NFT_TABLE} {{
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        {chr(10).join(statements)}
    }}
}}
"""


def apply_ingress_mss_rules(cfg: dict[str, Any], rules: list[dict[str, Any]], wan: str | None) -> int | None:
    """Install persistent MSS rules and remove the successful manual probe."""
    ruleset = build_mss_ruleset(cfg, rules, wan) if rules and wan else None
    if ruleset:
        # Replace the permanent table in one nftables transaction. If parsing or
        # kernel validation fails, the previous working table remains active.
        exists = run(["nft", "list", "table", "inet", MSS_NFT_TABLE], check=False).returncode == 0
        if exists:
            ruleset = f"delete table inet {MSS_NFT_TABLE}\n" + ruleset
        result = run(["nft", "-f", "-"], input_text=ruleset, check=False)
        if result.returncode != 0:
            raise PawFwdError(f"Erro ao aplicar MSS clamp TCP: {result.stderr.strip()}")
        mss = validate_tcp_mss(cfg.get("tcp_mss", TCP_MSS_DEFAULT))
        # The permanent table is active now; the temporary test table can
        # be removed without leaving a gap in the working path.
        run(["nft", "delete", "table", "inet", MSS_PROBE_NFT_TABLE], check=False)
        return mss
    # No TCP forwards remain: remove both managed and temporary test rules.
    run(["nft", "delete", "table", "inet", MSS_NFT_TABLE], check=False)
    run(["nft", "delete", "table", "inet", MSS_PROBE_NFT_TABLE], check=False)
    return None


def apply_ingress_rules(cfg: dict[str, Any]) -> None:
    peers = {p["tunnel_ip"] for p in cfg.get("peers", [])}
    rules = [validate_rule(r) for r in cfg.get("rules", [])]
    for rule in rules:
        if rule["peer_ip"] not in peers:
            raise PawFwdError(f"A regra {rule['public_port']} referencia um peer não cadastrado ({rule['peer_ip']}).")
    wan = public_interface() if rules else None
    if rules and not wan:
        raise PawFwdError("Não consegui detectar a interface pública da VPS; não vou criar DNAT amplo.")
    # Remove only PawFwd-owned tables; do not touch other firewall tables.
    run(["nft", "delete", "table", "ip", NFT_TABLE], check=False)
    rebuild_ufw_rules(cfg, rules, wan)
    if not rules:
        apply_ingress_mss_rules(cfg, rules, wan)
        return

    prerouting: list[str] = []
    forwarding: list[str] = []
    postrouting: list[str] = []
    for rule in rules:
        p, tp, proto, peer_ip = rule["public_port"], rule["target_port"], rule["proto"], rule["peer_ip"]
        prerouting.append(
            f'iifname "{wan}" {proto} dport {p} dnat to {peer_ip}:{tp}'
        )
        forwarding.append(
            f'oifname "{WG_IFACE}" ip daddr {peer_ip} {proto} dport {tp} accept'
        )
        forwarding.append(
            f'iifname "{WG_IFACE}" ip saddr {peer_ip} {proto} sport {tp} ct state established,related accept'
        )
        if not rule["preserve_ip"]:
            postrouting.append(
                f'oifname "{WG_IFACE}" ip daddr {peer_ip} {proto} dport {tp} masquerade'
            )

    ruleset = f"""
table ip {NFT_TABLE} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        {chr(10).join(prerouting)}
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        {chr(10).join(forwarding)}
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        {chr(10).join(postrouting)}
    }}
}}
"""
    result = run(["nft", "-f", "-"], input_text=ruleset, check=False)
    if result.returncode != 0:
        raise PawFwdError(f"Erro ao aplicar regras nftables: {result.stderr.strip()}")

    # Install MSS clamping after DNAT/forwarding exists. The two nft transactions
    # are individually atomic; on failure, the working probe rules are retained.
    mss = apply_ingress_mss_rules(cfg, rules, wan)
    if mss is not None:
        say(f"[i] MSS clamp TCP ativo: {mss} (SYN e SYN-ACK).")

def cleanup_owned_ip_rules(previous: list[dict[str, Any]]) -> None:
    for item in previous:
        kind = item.get("kind")
        if kind == "fwmark":
            command = [
                "ip", "-4", "rule", "del", "pref", str(item["priority"]),
                "fwmark", WG_FWMARK, "table", "main",
            ]
        elif kind == "return_mark":
            command = [
                "ip", "-4", "rule", "del", "pref", str(item["priority"]),
                "fwmark", RETURN_FWMARK, "table", RT_TABLE_ID,
            ]
        else:  # Clean up source-port rules created by early v2 development builds.
            command = [
                "ip", "-4", "rule", "del", "pref", str(item["priority"]),
                "ipproto", item["proto"], "sport", str(item["sport"]),
                "table", RT_TABLE_ID,
            ]
        run(command, check=False)


def cleanup_stale_table_rules() -> None:
    """Clean PawFwd routing rules left behind by an interrupted apply."""
    listing = run(["ip", "-4", "rule", "show"], check=False)
    for line in listing.stdout.splitlines():
        if f"lookup {RT_TABLE_ID}" not in line and f"table {RT_TABLE_ID}" not in line:
            continue
        parts = line.replace(":", " ", 1).split()
        if not parts or not parts[0].isdigit():
            continue
        pref = parts[0]
        if "ipproto" not in parts or "sport" not in parts:
            continue
        proto = parts[parts.index("ipproto") + 1]
        sport = parts[parts.index("sport") + 1]
        while True:
            result = run([
                "ip", "-4", "rule", "del", "pref", pref,
                "ipproto", proto, "sport", sport, "table", RT_TABLE_ID,
            ], check=False)
            if result.returncode != 0:
                break

    # Remove orphaned PawFwd mark rules after a crash or interrupted upgrade.
    listing = run(["ip", "-4", "rule", "show"], check=False)
    for line in listing.stdout.splitlines():
        pref = line.split(":", 1)[0].strip()
        if not pref.isdigit():
            continue
        if f"fwmark {WG_FWMARK}" in line and "lookup main" in line:
            run(["ip", "-4", "rule", "del", "pref", pref,
                 "fwmark", WG_FWMARK, "table", "main"], check=False)
        elif f"fwmark {RETURN_FWMARK}" in line and f"lookup {RT_TABLE_ID}" in line:
            run(["ip", "-4", "rule", "del", "pref", pref,
                 "fwmark", RETURN_FWMARK, "table", RT_TABLE_ID], check=False)


def next_rule_priority(used: set[int], candidate: int) -> int:
    while candidate in used and candidate <= RULE_PRIORITY_MAX:
        candidate += 1
    if candidate > RULE_PRIORITY_MAX:
        raise PawFwdError("Não há prioridades livres para as regras de roteamento de retorno.")
    return candidate


def rebuild_target_ufw_rules(rules: list[dict[str, Any]]) -> None:
    if not ufw_active():
        return
    listing = run(["ufw", "status", "numbered"], check=False).stdout
    numbers = []
    for line in listing.splitlines():
        if "PawFwd" in line:
            match = re.match(r"\[\s*(\d+)\]", line)
            if match:
                numbers.append(int(match.group(1)))
    for number in sorted(numbers, reverse=True):
        run(["ufw", "--force", "delete", str(number)], check=False)
    for rule in rules:
        run(["ufw", "allow", "in", "on", WG_IFACE, "to", "any",
             "port", str(rule["target_port"]), "proto", rule["proto"],
             "comment", "PawFwd"], check=False)


def target_connmark_ruleset() -> str:
    """Mark incoming PawFwd connections and restore the mark on their replies.

    This is independent of service ports, so it also works when Docker performs
    another DNAT from a host-published port to a container port.
    """
    return f"""
table ip {TARGET_NFT_TABLE} {{
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        iifname "{WG_IFACE}" ct mark set {RETURN_FWMARK}
        iifname != "{WG_IFACE}" ct mark {RETURN_FWMARK} meta mark set ct mark
    }}
    chain output {{
        type route hook output priority mangle; policy accept;
        ct mark {RETURN_FWMARK} meta mark set ct mark
    }}
}}
"""


def apply_target_return_routes(cfg: dict[str, Any]) -> None:
    old = cfg.get("routing_rules", [])
    cleanup_owned_ip_rules(old)
    cleanup_stale_table_rules()
    run(["ip", "-4", "route", "flush", "table", RT_TABLE_ID], check=False)
    target_rules = [validate_rule(r) for r in cfg.get("rules", [])]
    rebuild_target_ufw_rules(target_rules)
    preserved = [r for r in target_rules if r.get("preserve_ip")]
    if not preserved:
        run(["nft", "delete", "table", "ip", TARGET_NFT_TABLE], check=False)
        cfg["routing_rules"] = []
        save_config(cfg)
        return

    target_ip = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)
    tunnel_network = cfg.get("ingress_peer", {}).get("tunnel_network", TUNNEL_NETWORK)
    run(["ip", "-4", "route", "replace", tunnel_network,
         "dev", WG_IFACE, "src", target_ip, "table", RT_TABLE_ID])
    run(["ip", "-4", "route", "replace", "default", "dev", WG_IFACE,
         "table", RT_TABLE_ID])

    # Preserve the original client address in conntrack, then put only reply
    # packets onto the marked policy-routing table. Service source ports are
    # deliberately not used: Docker can rewrite those before replies are sent.
    run(["nft", "delete", "table", "ip", TARGET_NFT_TABLE], check=False)
    result = run(["nft", "-f", "-"], input_text=target_connmark_ruleset(), check=False)
    if result.returncode != 0:
        raise PawFwdError(f"Erro ao configurar marcas de conexão no target: {result.stderr.strip()}")

    listing = run(["ip", "-4", "rule", "show"]).stdout
    used = set()
    for line in listing.splitlines():
        pref = line.split(":", 1)[0].strip()
        if pref.isdigit():
            used.add(int(pref))

    created = []
    # WireGuard's own outer UDP packets use the normal host routing table,
    # avoiding an encapsulation loop through the policy table.
    mark_priority = next_rule_priority(used, WG_MARK_RULE_BASE)
    run(["ip", "-4", "rule", "add", "pref", str(mark_priority),
         "fwmark", WG_FWMARK, "table", "main"])
    created.append({"kind": "fwmark", "priority": mark_priority})
    used.add(mark_priority)

    return_priority = next_rule_priority(used, RULE_PRIORITY_BASE)
    run(["ip", "-4", "rule", "add", "pref", str(return_priority),
         "fwmark", RETURN_FWMARK, "table", RT_TABLE_ID])
    created.append({"kind": "return_mark", "priority": return_priority})
    cfg["routing_rules"] = created
    save_config(cfg)

def apply_local(cfg: dict[str, Any]) -> None:
    if not interface_exists():
        if cfg.get("role") == "target" and not cfg.get("ingress_peer"):
            raise PawFwdError("O pareamento com a VPS ainda não foi concluído. Rode 'sudo paw-fwd init <IP-DA-VPS>'.")
        raise PawFwdError(f"A interface {WG_IFACE} não está ativa. Rode 'sudo systemctl start wg-quick@paw-fwd'.")
    persist_sysctls()
    if cfg["role"] == "ingress":
        apply_ingress_rules(cfg)
    else:
        apply_target_return_routes(cfg)


def sync_rules_to_ingress(cfg: dict[str, Any]) -> None:
    control = cfg.get("control")
    if not control:
        raise PawFwdError("Não há conexão de controle configurada. Rode 'paw-fwd init <IP-VPS>' novamente.")
    payload = {
        "rules": [
            {**rule, "peer_ip": str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)}
            for rule in cfg.get("rules", [])
        ],
    }
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    remote_output = ssh_remote(
        control["host"], control["user"], int(control.get("port", 22)),
        ["sudo", "-n", str(INSTALL_PATH), "rules", "import", "--payload", encoded],
    )
    if remote_output:
        say(f"[i] VPS: {remote_output.splitlines()[-1]}")


def update_rules(cfg: dict[str, Any], spec: dict[str, Any], *, remove: bool,
                 preserve_ip: bool = False) -> None:
    if cfg["role"] != "target":
        raise PawFwdError("Gerencie os encaminhamentos a partir do target (servidor doméstico). Assim as rotas de retorno também são atualizadas.")
    selected = set(spec["protocols"])
    public_port = spec["public_port"]
    if remove:
        cfg["rules"] = [
            r for r in cfg.get("rules", [])
            if not (r["public_port"] == public_port and r["proto"] in selected)
        ]
        message = f"removido {public_port} ({', '.join(sorted(selected))})"
    else:
        # Replacing only the selected protocol(s) leaves the other protocol intact.
        cfg["rules"] = [
            r for r in cfg.get("rules", [])
            if not (r["public_port"] == public_port and r["proto"] in selected)
        ]
        peer_ip = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)
        for proto in sorted(selected):
            cfg["rules"].append({
                "public_port": public_port,
                "target_port": spec["target_port"],
                "proto": proto,
                "preserve_ip": preserve_ip,
                "peer_ip": peer_ip,
            })
        message = f"{public_port} → {spec['target_port']} ({', '.join(sorted(selected))})"
    cfg["rules"] = [validate_rule(r) for r in cfg.get("rules", [])]
    save_config(cfg)
    apply_local(cfg)
    sync_rules_to_ingress(cfg)
    if remove:
        say(f"[-] Encaminhamento {message}. Até a próxima conexão. :3")
    else:
        mode = "IP original preservado" if preserve_ip else "SNAT"
        say(f"[+] Encaminhamento {message} configurado via PawFwd. ({mode})")


def import_rules(payload: str) -> None:
    cfg = load_config()
    if cfg.get("role") != "ingress":
        raise PawFwdError("A sincronização de regras deve chegar ao ingress.")
    try:
        decoded = json.loads(base64.b64decode(payload, validate=True))
    except Exception as exc:
        raise PawFwdError("Payload de sincronização inválido.") from exc
    rules = expand_stored_rules(decoded.get("rules", []))
    known_peers = {peer["tunnel_ip"] for peer in cfg.get("peers", [])}
    for rule in rules:
        if rule["peer_ip"] not in known_peers:
            raise PawFwdError(f"Peer {rule['peer_ip']} não está cadastrado nesta VPS.")
    cfg["rules"] = rules
    save_config(cfg)
    apply_local(cfg)
    print(f"Regras sincronizadas: {len(rules)} protocolo(s) ativo(s).")


def cmd_list(cfg: dict[str, Any]) -> None:
    say(f"PawFwd {VERSION} · {cfg['role']} · interface {WG_IFACE}")
    if cfg["role"] == "ingress":
        say(f"WireGuard UDP: {cfg['wireguard']['listen_port']}")
        say(f"Peers: {len(cfg.get('peers', []))}")
        tcp_enabled = any(rule.get("proto") == "tcp" for rule in cfg.get("rules", []))
        say(f"TCP MSS clamp: até {cfg.get('tcp_mss', TCP_MSS_DEFAULT)} bytes" if tcp_enabled else "TCP MSS clamp: aguardando encaminhamento TCP")
    else:
        peer = cfg.get("ingress_peer")
        if peer:
            say(f"Endpoint: {peer['endpoint']}:{peer['listen_port']}")
            say(f"Túnel: {cfg['wireguard'].get('address', '(endereço pendente)')}")
        else:
            pending = cfg.get("pending_endpoint", "não informado")
            say(f"Pareamento: pendente/incompleto · VPS {pending}")
            say("Rode novamente 'sudo paw-fwd init <IP-DA-VPS>' para concluir com a mesma chave.")
    say("")
    if not cfg.get("rules"):
        say("Nenhum encaminhamento configurado. (Os bigodes estão em repouso.)")
        return
    say(f"{'PUBLIC':<9} {'TARGET':<9} {'PROTO':<8} {'MODE':<12}")
    say("-" * 43)
    for rule in sorted(cfg["rules"], key=lambda r: (r["public_port"], r["proto"])):
        mode = "preserve-ip" if rule.get("preserve_ip") else "SNAT"
        say(f"{rule['public_port']:<9} {rule['target_port']:<9} {rule['proto'].upper():<8} {mode:<12}")


def cmd_status(cfg: dict[str, Any]) -> None:
    say(f"PawFwd {VERSION} status")
    wg = run(["wg", "show", WG_IFACE], check=False)
    say("\n[WireGuard]")
    say(wg.stdout.strip() if wg.returncode == 0 else "interface indisponível")
    say("\n[Encaminhamentos]")
    cmd_list(cfg)
    if cfg["role"] == "target":
        say("\n[Policy routing]")
        routes = run(["ip", "-4", "route", "show", "table", RT_TABLE_ID], check=False)
        say(routes.stdout.strip() or "(nenhuma rota especial)")
        rules = run(["ip", "-4", "rule", "show"], check=False)
        say(rules.stdout.strip())
    if cfg["role"] == "ingress":
        nft = run(["nft", "list", "table", "ip", NFT_TABLE], check=False)
        say("\n[nftables]")
        say(nft.stdout.strip() if nft.returncode == 0 else "(nenhuma regra ativa)")
        mss = run(["nft", "list", "table", "inet", MSS_NFT_TABLE], check=False)
        say("\n[TCP MSS clamp]")
        say(mss.stdout.strip() if mss.returncode == 0 else "(sem regras TCP; normal sem encaminhamentos TCP)")


def cmd_diag(cfg: dict[str, Any]) -> None:
    say("=== PawFwd diagnostics ===")
    say(f"Version: {VERSION}\nRole: {cfg['role']}\nInterface: {WG_IFACE}")
    say("\n[WireGuard link]")
    say(run(["ip", "-o", "link", "show", "dev", WG_IFACE], check=False).stdout.strip() or "interface ausente")
    say("\n[WireGuard]")
    say(run(["wg", "show", WG_IFACE], check=False).stdout.strip() or "sem handshake/configuração")
    say("\n[UDP listeners]")
    for port, owners in sorted(wireguard_listen_ports().items()):
        say(f"WireGuard UDP {port}: {', '.join(owners)}")
    say("\n[Routes]")
    say(run(["ip", "-4", "route", "show"], check=False).stdout.strip())
    if cfg["role"] == "target":
        say("\n[Return policy table]")
        say(run(["ip", "-4", "route", "show", "table", RT_TABLE_ID], check=False).stdout.strip() or "(vazia)")
        target_table = run(["nft", "list", "table", "ip", TARGET_NFT_TABLE], check=False)
        say("\n[Return conntrack marks]")
        say(target_table.stdout.strip() if target_table.returncode == 0 else "(sem marcação; normal sem preserve-ip)")
    else:
        say("\n[nftables]")
        table = run(["nft", "list", "table", "ip", NFT_TABLE], check=False)
        say(table.stdout.strip() if table.returncode == 0 else "(tabela ausente; normal se ainda não há forwards)")
        mss = run(["nft", "list", "table", "inet", MSS_NFT_TABLE], check=False)
        say("\n[TCP MSS clamp]")
        say(mss.stdout.strip() if mss.returncode == 0 else "(tabela ausente; normal sem encaminhamentos TCP)")
    if cfg["role"] == "ingress":
        say(f"\n[TCP MSS]\nConfigured ceiling: {cfg.get('tcp_mss', TCP_MSS_DEFAULT)} bytes")
        say(f"\n[Firewall hint]\nGaranta UDP {cfg['wireguard']['listen_port']} liberado também no firewall do provedor VPS.")


def install_command() -> None:
    install_self()
    say(f"[+] PawFwd instalado em {INSTALL_PATH}. Agora rode 'paw-fwd init'. :3")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="paw-fwd",
        description="PawFwd — encaminhamento de portas com túnel WireGuard dedicado.",
        epilog="Dica: paw-fwd add 25505 publica TCP+UDP; use /tcp ou /udp para escolher um só. O ingress aplica MSS clamp TCP automaticamente.",
    )
    parser.add_argument("--version", action="version", version=f"PawFwd {VERSION}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="Inicializa a VPS ou conecta um servidor target")
    init.add_argument("endpoint", nargs="?", help="IP/hostname público da VPS (modo target)")
    init.add_argument("--role", choices=["ingress"], help="Use --role ingress na VPS pública")
    init.add_argument("--listen-port", type=int, default=None, help="Porta UDP WireGuard na VPS (padrão: 51820; escolhe outra se estiver ocupada)")
    init.add_argument("--mss", type=int, default=None, help=f"Limite MSS TCP dos encaminhamentos (padrão: {TCP_MSS_DEFAULT}; faixa {TCP_MSS_MIN}-{TCP_MSS_MAX})")
    init.add_argument("--ssh-host", help="Host usado para SSH; pode ser o nome Tailscale da VPS")
    init.add_argument("--ssh-user", help="Usuário SSH na VPS (padrão: usuário local)")
    init.add_argument("--ssh-port", type=int, default=22, help="Porta SSH da VPS")
    init.add_argument("--name", help="Nome deste peer (padrão: hostname)")

    sub.add_parser("install", help="Instala o executável em /usr/local/bin")
    sub.add_parser("list", aliases=["ls"], help="Lista encaminhamentos")
    sub.add_parser("status", help="Mostra o estado do túnel e dos encaminhamentos")
    sub.add_parser("diag", help="Diagnóstico de rede, WireGuard, rotas e nftables")
    sub.add_parser("apply", help=argparse.SUPPRESS)
    sub.add_parser("sync", help="Sincroniza as regras do target para a VPS")

    add = sub.add_parser("add", help="Adiciona um encaminhamento: PUBLIC[:TARGET][/tcp|/udp]")
    add.add_argument("spec", help="Ex.: 25505, 25505:25565, 19132/udp")
    add.add_argument("--preserve-ip", action="store_true", help="Preserva o IP real do cliente no servidor")

    remove = sub.add_parser("remove", aliases=["rm"], help="Remove um encaminhamento")
    remove.add_argument("spec", help="Ex.: 25505 (remove TCP+UDP) ou 25505/udp")

    peer = sub.add_parser("peer", help=argparse.SUPPRESS)
    peer_sub = peer.add_subparsers(dest="peer_command", required=True)
    register = peer_sub.add_parser("register", help=argparse.SUPPRESS)
    register.add_argument("--public-key", required=True)
    register.add_argument("--name", required=True)

    rules = sub.add_parser("rules", help=argparse.SUPPRESS)
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    imp = rules_sub.add_parser("import", help=argparse.SUPPRESS)
    imp.add_argument("--payload", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "install":
            require_root()
            install_command()
            return 0

        require_root()

        if args.command == "init":
            if args.listen_port is not None and (args.listen_port < 1 or args.listen_port > 65535):
                raise PawFwdError("A porta UDP do WireGuard precisa estar entre 1 e 65535.")
            if args.role == "ingress":
                if args.endpoint:
                    raise PawFwdError("No ingress, não informe endpoint; use 'paw-fwd init --role ingress'.")
                init_ingress(args.listen_port, args.mss)
            else:
                if args.mss is not None:
                    raise PawFwdError("--mss só pode ser usado no ingress: paw-fwd init --role ingress --mss 1200.")
                if not args.endpoint:
                    raise PawFwdError("Informe o IP público da VPS: 'paw-fwd init <IP-DA-VPS>'.")
                init_target(args.endpoint, args.ssh_host, args.ssh_user, args.ssh_port, args.name)
            return 0

        if args.command == "peer":
            if args.peer_command == "register":
                peer_register(args.public_key, args.name)
                return 0

        if args.command == "rules":
            if args.rules_command == "import":
                import_rules(args.payload)
                return 0

        cfg = load_config()
        if args.command in ("list", "ls"):
            cmd_list(cfg)
        elif args.command == "status":
            cmd_status(cfg)
        elif args.command == "diag":
            cmd_diag(cfg)
        elif args.command == "apply":
            apply_local(cfg)
        elif args.command == "sync":
            if cfg["role"] != "target":
                raise PawFwdError("Execute 'sync' no target, que envia as regras para a VPS.")
            apply_local(cfg)
            sync_rules_to_ingress(cfg)
            say("[+] Sincronização concluída. Tudo no trilho. :3")
        elif args.command == "add":
            spec = parse_port_spec(args.spec)
            update_rules(cfg, spec, remove=False, preserve_ip=args.preserve_ip)
        elif args.command in ("remove", "rm"):
            spec = parse_port_spec(args.spec)
            update_rules(cfg, spec, remove=True)
        else:
            parser.error("comando inválido")
        return 0
    except PawFwdError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[*] Interrompido. O PawFwd continua no estado anterior.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
