"""Gerenciamento e aplicação dos encaminhamentos."""

from __future__ import annotations

import base64
import ipaddress
import json
from typing import Any

from pawfwd.config import expand_stored_rules, load_config, save_config, validate_rule
from pawfwd.constants import INSTALL_PATH, WG_IFACE
from pawfwd.errors import PawFwdError
from pawfwd.firewall import apply_ingress_rules
from pawfwd.install import persist_sysctls
from pawfwd.network import interface_exists
from pawfwd.routing import apply_target_return_routes
from pawfwd.ssh import ssh_remote
from pawfwd.system import say


def apply_local(cfg: dict[str, Any]) -> None:
    if not interface_exists():
        if cfg.get("role") == "target" and not cfg.get("ingress_peer"):
            raise PawFwdError("O pareamento com a VPS ainda não foi concluído. Rode 'sudo pawfwd init <IP-DA-VPS>'.")
        raise PawFwdError(f"A interface {WG_IFACE} não está ativa. Rode 'sudo systemctl start wg-quick@paw-fwd'.")
    persist_sysctls()
    if cfg["role"] == "ingress":
        apply_ingress_rules(cfg)
    else:
        apply_target_return_routes(cfg)


def sync_rules_to_ingress(cfg: dict[str, Any]) -> None:
    control = cfg.get("control")
    if not control:
        raise PawFwdError("Não há conexão de controle configurada. Rode 'pawfwd init <IP-VPS>' novamente.")
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
