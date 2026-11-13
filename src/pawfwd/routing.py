"""Regras de policy routing que preservam o IP do cliente."""

from __future__ import annotations

import ipaddress
from typing import Any

from pawfwd.config import save_config, validate_rule
from pawfwd.constants import (
    RETURN_FWMARK,
    RT_TABLE_ID,
    RULE_PRIORITY_BASE,
    RULE_PRIORITY_MAX,
    TARGET_NFT_TABLE,
    TUNNEL_NETWORK,
    WG_FWMARK,
    WG_IFACE,
    WG_MARK_RULE_BASE,
)
from pawfwd.errors import PawFwdError
from pawfwd.firewall import rebuild_target_ufw_rules, target_connmark_ruleset
from pawfwd.system import run


def cleanup_owned_ip_rules(previous: list[dict[str, Any]]) -> None:
    for item in previous:
        kind = item.get("kind")
        if kind == "fwmark":
            command = [
                "ip",
                "-4",
                "rule",
                "del",
                "pref",
                str(item["priority"]),
                "fwmark",
                WG_FWMARK,
                "table",
                "main",
            ]
        elif kind == "return_mark":
            command = [
                "ip",
                "-4",
                "rule",
                "del",
                "pref",
                str(item["priority"]),
                "fwmark",
                RETURN_FWMARK,
                "table",
                RT_TABLE_ID,
            ]
        else:  # Clean up source-port rules created by early v2 development builds.
            command = [
                "ip",
                "-4",
                "rule",
                "del",
                "pref",
                str(item["priority"]),
                "ipproto",
                item["proto"],
                "sport",
                str(item["sport"]),
                "table",
                RT_TABLE_ID,
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
            result = run(
                [
                    "ip",
                    "-4",
                    "rule",
                    "del",
                    "pref",
                    pref,
                    "ipproto",
                    proto,
                    "sport",
                    sport,
                    "table",
                    RT_TABLE_ID,
                ],
                check=False,
            )
            if result.returncode != 0:
                break

    # Remove orphaned PawFwd mark rules after a crash or interrupted upgrade.
    listing = run(["ip", "-4", "rule", "show"], check=False)
    for line in listing.stdout.splitlines():
        pref = line.split(":", 1)[0].strip()
        if not pref.isdigit():
            continue
        if f"fwmark {WG_FWMARK}" in line and "lookup main" in line:
            run(["ip", "-4", "rule", "del", "pref", pref, "fwmark", WG_FWMARK, "table", "main"], check=False)
        elif f"fwmark {RETURN_FWMARK}" in line and f"lookup {RT_TABLE_ID}" in line:
            run(["ip", "-4", "rule", "del", "pref", pref, "fwmark", RETURN_FWMARK, "table", RT_TABLE_ID], check=False)


def next_rule_priority(used: set[int], candidate: int) -> int:
    while candidate in used and candidate <= RULE_PRIORITY_MAX:
        candidate += 1
    if candidate > RULE_PRIORITY_MAX:
        raise PawFwdError("Não há prioridades livres para as regras de roteamento de retorno.")
    return candidate


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
    run(["ip", "-4", "route", "replace", tunnel_network, "dev", WG_IFACE, "src", target_ip, "table", RT_TABLE_ID])
    run(["ip", "-4", "route", "replace", "default", "dev", WG_IFACE, "table", RT_TABLE_ID])

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
    run(["ip", "-4", "rule", "add", "pref", str(mark_priority), "fwmark", WG_FWMARK, "table", "main"])
    created.append({"kind": "fwmark", "priority": mark_priority})
    used.add(mark_priority)

    return_priority = next_rule_priority(used, RULE_PRIORITY_BASE)
    run(["ip", "-4", "rule", "add", "pref", str(return_priority), "fwmark", RETURN_FWMARK, "table", RT_TABLE_ID])
    created.append({"kind": "return_mark", "priority": return_priority})
    cfg["routing_rules"] = created
    save_config(cfg)
