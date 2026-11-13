from pawfwd.firewall import build_mss_ruleset
from pawfwd.wireguard import serialize_wg_config

KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_config_wireguard_do_ingress():
    cfg = {
        "role": "ingress",
        "wireguard": {"private_key": KEY, "address": "10.77.0.1/24", "listen_port": 51820},
        "peers": [{"public_key": KEY, "tunnel_ip": "10.77.0.2"}],
    }
    text = serialize_wg_config(cfg)
    assert "ListenPort = 51820" in text
    assert "AllowedIPs = 10.77.0.2/32" in text
    assert "Table = off" in text
    assert "FwMark" not in text


def test_config_wireguard_do_target():
    cfg = {
        "role": "target",
        "wireguard": {"private_key": KEY, "address": "10.77.0.2/32"},
        "ingress_peer": {"public_key": KEY, "endpoint": "203.0.113.10", "listen_port": 51820},
    }
    text = serialize_wg_config(cfg)
    assert "FwMark = 0x77" in text
    assert "Endpoint = 203.0.113.10:51820" in text
    assert "AllowedIPs = 0.0.0.0/0" in text
    assert "PersistentKeepalive = 25" in text
    assert "ListenPort" not in text


def test_mss_sem_regras_tcp_nao_gera_tabela():
    cfg = {"tcp_mss": 1200}
    rules = [{"public_port": 19132, "target_port": 19132, "proto": "udp", "peer_ip": "10.77.0.2", "preserve_ip": False}]
    assert build_mss_ruleset(cfg, rules, "eth0") is None


def test_mss_com_regra_tcp_limita_syn_e_syn_ack():
    cfg = {"tcp_mss": 1200}
    rules = [{"public_port": 25565, "target_port": 25565, "proto": "tcp", "peer_ip": "10.77.0.2", "preserve_ip": False}]
    ruleset = build_mss_ruleset(cfg, rules, "eth0")
    assert 'iifname "eth0" tcp dport 25565' in ruleset
    assert ruleset.count("tcp option maxseg size set 1200") == 2
