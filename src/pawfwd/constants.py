"""Constantes de caminhos, portas e marcas usadas pelo PawFwd."""

from __future__ import annotations

from pathlib import Path

CONFIG_DIR = Path("/etc/paw-fwd")


CONFIG_PATH = CONFIG_DIR / "config.json"


WG_DIR = Path("/etc/wireguard")


WG_CONFIG = WG_DIR / "paw-fwd.conf"


WG_IFACE = "paw-fwd"


WG_PORT_DEFAULT = 51820


INGRESS_TUNNEL_IP = "10.77.0.1"


TUNNEL_NETWORK = "10.77.0.0/24"


TUNNEL_NETWORK_CANDIDATES = [
    "10.77.0.0/24",
    "10.78.0.0/24",
    "10.79.0.0/24",
    "10.90.0.0/24",
    "10.250.0.0/24",
    "172.31.240.0/24",
    "192.168.254.0/24",
    "192.168.253.0/24",
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


INSTALL_PATH = Path("/usr/local/bin/pawfwd")


SYSTEMD_UNIT = Path("/etc/systemd/system/paw-fwd.service")


SYSCTL_FILE = Path("/etc/sysctl.d/99-paw-fwd.conf")
