import json

import pytest

from pawfwd.errors import PawFwdError
from pawfwd.target import parse_peer_registration

KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PAYLOAD = {
    "target_tunnel_ip": "10.77.0.2",
    "ingress_tunnel_ip": "10.77.0.1",
    "ingress_public_key": KEY,
    "listen_port": 51820,
}


def test_extrai_json_mesmo_com_mensagens_do_ssh():
    output = "[sudo] senha para usuario:\r\n" + json.dumps(PAYLOAD) + "\r\nConnection to vps closed.\r\n"
    assert parse_peer_registration(output)["target_tunnel_ip"] == "10.77.0.2"


def test_saida_sem_json_levanta_erro():
    with pytest.raises(PawFwdError, match="registro de pareamento válido"):
        parse_peer_registration("erro qualquer")


def test_json_sem_campos_obrigatorios_levanta_erro():
    incomplete = {k: v for k, v in PAYLOAD.items() if k != "listen_port"}
    with pytest.raises(PawFwdError):
        parse_peer_registration(json.dumps(incomplete))
