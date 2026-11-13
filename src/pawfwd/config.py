"""Leitura, escrita e validação da configuração e das regras."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from pawfwd.constants import (
    CONFIG_PATH,
    INGRESS_TUNNEL_IP,
    TCP_MSS_MAX,
    TCP_MSS_MIN,
    TUNNEL_NETWORK,
    WG_MTU,
)
from pawfwd.errors import PawFwdError
from pawfwd.system import atomic_write, run


def load_config(required: bool = True) -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        if required:
            raise PawFwdError("PawFwd ainda não foi inicializado. Comece com 'pawfwd init'.")
        return {}
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PawFwdError(f"Não consegui ler {CONFIG_PATH}: {exc}") from exc
    if cfg.get("schema_version") != 2:
        raise PawFwdError(
            "Esta configuração não é da versão 2. A configuração antiga foi preservada; faça backup antes de migrar."
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
        raise PawFwdError(f"Formato inválido: {spec!r}. Use PORTA, PORTA:DESTINO, PORTA/tcp ou PORTA:DESTINO/udp.")
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
        network = str(
            ipaddress.IPv4Network(cfg.get("ingress_peer", {}).get("tunnel_network", TUNNEL_NETWORK), strict=False)
        )
    if cfg.get("ingress_tunnel_ip"):
        ingress_ip = str(ipaddress.IPv4Address(cfg["ingress_tunnel_ip"]))
    elif cfg.get("role") == "ingress":
        ingress_ip = str(ipaddress.IPv4Interface(cfg["wireguard"]["address"]).ip)
    else:
        ingress_ip = str(ipaddress.IPv4Address(cfg.get("ingress_peer", {}).get("tunnel_ip", INGRESS_TUNNEL_IP)))
    return network, ingress_ip


def validate_tcp_mss(value: Any) -> int:
    """Validate the TCP MSS ceiling used on forwarded SYN/SYN-ACK packets."""
    try:
        mss = int(value)
    except (TypeError, ValueError) as exc:
        raise PawFwdError(f"MSS TCP inválido: {value!r}.") from exc
    if not TCP_MSS_MIN <= mss <= TCP_MSS_MAX:
        raise PawFwdError(f"MSS TCP precisa estar entre {TCP_MSS_MIN} e {TCP_MSS_MAX} para MTU {WG_MTU}.")
    return mss
