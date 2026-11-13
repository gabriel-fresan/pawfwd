"""Instalação do executável, unidade systemd e sysctls."""

from __future__ import annotations

import sys

from pawfwd.constants import INSTALL_PATH, SYSCTL_FILE, SYSTEMD_UNIT, WG_IFACE
from pawfwd.errors import PawFwdError
from pawfwd.system import atomic_write, run, say


def install_self() -> None:
    """Grava um launcher em INSTALL_PATH que usa o mesmo Python que instalou o pacote."""
    launcher = (
        f"#!{sys.executable}\n"
        "# Gerado por 'pawfwd init' ou 'pawfwd install'. Não edite à mão.\n"
        "import sys\n"
        "\n"
        "from pawfwd.cli import main\n"
        "\n"
        "sys.exit(main())\n"
    )
    try:
        INSTALL_PATH.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(INSTALL_PATH, launcher, 0o755)
    except OSError as exc:
        raise PawFwdError(f"Não consegui instalar o executável em {INSTALL_PATH}: {exc}") from exc


def install_systemd() -> None:
    unit = f"""[Unit]
Description=PawFwd port forwarding rules
Documentation=man:wg-quick(8)
After=network-online.target wg-quick@paw-fwd.service
Wants=network-online.target
Requires=wg-quick@paw-fwd.service

[Service]
Type=oneshot
ExecStart={INSTALL_PATH} apply
ExecReload={INSTALL_PATH} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    atomic_write(SYSTEMD_UNIT, unit, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "wg-quick@paw-fwd.service", "paw-fwd.service"])


def persist_sysctls() -> None:
    # Do not change Tailscale's sysctls or the host-wide rp_filter policy.
    # The tunnel interface gets loose reverse-path filtering at apply time.
    content = "net.ipv4.ip_forward=1\n"
    atomic_write(SYSCTL_FILE, content, 0o644)
    run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
    run(["sysctl", "-q", "-w", f"net.ipv4.conf.{WG_IFACE}.rp_filter=2"])


def install_command() -> None:
    install_self()
    say(f"[+] PawFwd instalado em {INSTALL_PATH}. Agora rode 'pawfwd init'. :3")
