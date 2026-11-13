"""Saídas de status, listagem e diagnóstico."""

from __future__ import annotations

from typing import Any

from pawfwd import __version__ as VERSION
from pawfwd.constants import (
    MSS_NFT_TABLE,
    NFT_TABLE,
    RT_TABLE_ID,
    TARGET_NFT_TABLE,
    TCP_MSS_DEFAULT,
    WG_IFACE,
)
from pawfwd.network import wireguard_listen_ports
from pawfwd.system import run, say


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
            say("Rode novamente 'sudo pawfwd init <IP-DA-VPS>' para concluir com a mesma chave.")
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
