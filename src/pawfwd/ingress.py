"""Configuração do servidor público (VPS, ingress)."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Any

from pawfwd.config import (
    genkey,
    load_config,
    save_config,
    tunnel_details,
    validate_tcp_mss,
)
from pawfwd.constants import (
    CONFIG_DIR,
    INGRESS_TUNNEL_IP,
    TCP_MSS_DEFAULT,
    TUNNEL_NETWORK,
    WG_IFACE,
    WG_MTU,
    WG_PORT_DEFAULT,
)
from pawfwd.errors import PawFwdError
from pawfwd.firewall import open_wireguard_firewall
from pawfwd.install import install_self, install_systemd, persist_sysctls
from pawfwd.legacy import cleanup_legacy_installation
from pawfwd.network import choose_tunnel_network, interface_exists, select_listen_port
from pawfwd.system import ensure_dependencies, run, say
from pawfwd.wireguard import start_ingress_wireguard_with_diagnostics, write_wg_config


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
