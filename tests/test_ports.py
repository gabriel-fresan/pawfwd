import pytest

from pawfwd.config import parse_port_spec, validate_port
from pawfwd.errors import PawFwdError


def test_porta_simples_publica_tcp_e_udp():
    spec = parse_port_spec("25505")
    assert spec == {"public_port": 25505, "target_port": 25505, "protocols": ["tcp", "udp"]}


def test_porta_com_destino_diferente_e_protocolo_unico():
    spec = parse_port_spec("25505:25565/tcp")
    assert spec == {"public_port": 25505, "target_port": 25565, "protocols": ["tcp"]}


def test_udp_sem_destino():
    assert parse_port_spec("19132/udp")["protocols"] == ["udp"]


def test_protocolo_e_case_insensitive_e_espacos_sao_ignorados():
    assert parse_port_spec("  25505/TCP ")["protocols"] == ["tcp"]


@pytest.mark.parametrize("spec", ["abc", "25505/icmp", "25505:/tcp", "1.5"])
def test_formato_invalido_levanta_erro(spec):
    with pytest.raises(PawFwdError, match="Formato inválido"):
        parse_port_spec(spec)


@pytest.mark.parametrize("port", [0, 65536, "70000"])
def test_porta_fora_da_faixa_levanta_erro(port):
    with pytest.raises(PawFwdError):
        validate_port(port)
