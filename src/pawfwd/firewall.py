"""Regras nftables e UFW para DNAT, encaminhamento e MSS clamp."""

from __future__ import annotations

import re
import shutil
from typing import Any

from pawfwd.config import validate_rule, validate_tcp_mss
from pawfwd.constants import (
    MSS_NFT_TABLE,
    MSS_PROBE_NFT_TABLE,
    NFT_TABLE,
    RETURN_FWMARK,
    TARGET_NFT_TABLE,
    TCP_MSS_DEFAULT,
    WG_IFACE,
)
from pawfwd.errors import PawFwdError
from pawfwd.network import public_interface
from pawfwd.system import run, say


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


def ufw_active() -> bool:
    if not shutil.which("ufw"):
        return False
    result = run(["ufw", "status"], check=False)
    return "Status: active" in result.stdout


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
        run(
            [
                "ufw",
                "route",
                "allow",
                "in",
                "on",
                wan,
                "out",
                "on",
                WG_IFACE,
                "to",
                rule["peer_ip"],
                "port",
                str(rule["target_port"]),
                "proto",
                proto,
                "comment",
                "PawFwd",
            ],
            check=False,
        )


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
            f"tcp flags & (syn | ack) == syn "
            f"tcp option maxseg size > {mss} "
            f"tcp option maxseg size set {mss} counter"
        )
        statements.append(
            f'iifname "{WG_IFACE}" ip saddr {peer_ip} tcp sport {target_port} '
            f"tcp flags & (syn | ack) == (syn | ack) "
            f"tcp option maxseg size > {mss} "
            f"tcp option maxseg size set {mss} counter"
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
        prerouting.append(f'iifname "{wan}" {proto} dport {p} dnat to {peer_ip}:{tp}')
        forwarding.append(f'oifname "{WG_IFACE}" ip daddr {peer_ip} {proto} dport {tp} accept')
        forwarding.append(
            f'iifname "{WG_IFACE}" ip saddr {peer_ip} {proto} sport {tp} ct state established,related accept'
        )
        if not rule["preserve_ip"]:
            postrouting.append(f'oifname "{WG_IFACE}" ip daddr {peer_ip} {proto} dport {tp} masquerade')

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
        run(
            [
                "ufw",
                "allow",
                "in",
                "on",
                WG_IFACE,
                "to",
                "any",
                "port",
                str(rule["target_port"]),
                "proto",
                rule["proto"],
                "comment",
                "PawFwd",
            ],
            check=False,
        )


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
