"""Configuração do servidor doméstico (target)."""

from __future__ import annotations

import base64
import getpass
import ipaddress
import json
import os
import re
import socket
from typing import Any

from pawfwd.config import genkey, load_config, save_config
from pawfwd.constants import INSTALL_PATH, TUNNEL_NETWORK
from pawfwd.errors import PawFwdError
from pawfwd.install import install_self, install_systemd, persist_sysctls
from pawfwd.legacy import cleanup_legacy_installation
from pawfwd.ssh import ssh_remote
from pawfwd.system import ensure_dependencies, run, say
from pawfwd.wireguard import start_wireguard


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
    say("\nAgora você já pode usar 'sudo pawfwd add 25505'. :3\n")
