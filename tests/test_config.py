import pytest

from pawfwd.config import expand_stored_rules, tunnel_details, validate_rule, validate_tcp_mss
from pawfwd.constants import TCP_MSS_DEFAULT, TCP_MSS_MAX, TCP_MSS_MIN
from pawfwd.errors import PawFwdError


def test_validate_rule_preenche_defaults():
    rule = validate_rule({"public_port": 25505, "proto": "tcp", "peer_ip": "10.77.0.2"})
    assert rule == {
        "public_port": 25505,
        "target_port": 25505,
        "proto": "tcp",
        "preserve_ip": False,
        "peer_ip": "10.77.0.2",
    }


def test_validate_rule_rejeita_protocolo_desconhecido():
    with pytest.raises(PawFwdError, match="Protocolo interno inválido"):
        validate_rule({"public_port": 25505, "proto": "icmp", "peer_ip": "10.77.0.2"})


def test_expand_stored_rules_separa_both_em_tcp_e_udp():
    rules = expand_stored_rules([{"public_port": 25505, "proto": "both", "peer_ip": "10.77.0.2"}])
    assert sorted(r["proto"] for r in rules) == ["tcp", "udp"]


def test_expand_stored_rules_mantem_uma_regra_por_porta_e_protocolo():
    rules = expand_stored_rules([
        {"public_port": 1, "target_port": 2, "proto": "tcp", "peer_ip": "10.77.0.2"},
        {"public_port": 1, "target_port": 3, "proto": "tcp", "peer_ip": "10.77.0.2"},
    ])
    assert len(rules) == 1
    assert rules[0]["target_port"] == 3


def test_validate_tcp_mss_aceita_padrao_e_limites():
    assert validate_tcp_mss(TCP_MSS_DEFAULT) == TCP_MSS_DEFAULT
    assert validate_tcp_mss(TCP_MSS_MIN) == TCP_MSS_MIN
    assert validate_tcp_mss(TCP_MSS_MAX) == TCP_MSS_MAX


@pytest.mark.parametrize("value", [TCP_MSS_MIN - 1, TCP_MSS_MAX + 1, "abc"])
def test_validate_tcp_mss_rejeita_fora_da_faixa(value):
    with pytest.raises(PawFwdError):
        validate_tcp_mss(value)


def test_tunnel_details_ingress_usa_endereco_da_interface():
    cfg = {"role": "ingress", "wireguard": {"address": "10.77.0.1/24"}}
    assert tunnel_details(cfg) == ("10.77.0.0/24", "10.77.0.1")


def test_tunnel_details_target_usa_configuracao_do_ingress():
    cfg = {"role": "target", "ingress_peer": {"tunnel_network": "10.78.0.0/24", "tunnel_ip": "10.78.0.1"}}
    assert tunnel_details(cfg) == ("10.78.0.0/24", "10.78.0.1")


def test_tunnel_details_target_sem_dados_usa_padroes():
    assert tunnel_details({"role": "target"}) == ("10.77.0.0/24", "10.77.0.1")
