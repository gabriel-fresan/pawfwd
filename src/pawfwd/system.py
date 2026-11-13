"""Utilitários de sistema: execução de comandos, permissões e escrita atômica."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from pawfwd.errors import PawFwdError


def say(message: str = "") -> None:
    print(message)


def run(
    command: list[str], *, input_text: str | None = None, check: bool = True, capture: bool = True
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=capture,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PawFwdError(f"Comando não encontrado: {command[0]}. Instale as dependências do PawFwd.") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "sem detalhes").strip()
        raise PawFwdError(f"Falha ao executar {' '.join(command)}: {detail}")
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise PawFwdError("Preciso de privilégios de administrador. Rode com sudo.")


def ensure_dependencies() -> None:
    required = ["ip", "wg", "wg-quick", "systemctl", "ssh", "sysctl", "nft"]
    missing = [item for item in required if shutil.which(item) is None]
    if missing:
        raise PawFwdError(
            "Dependências ausentes: "
            + ", ".join(missing)
            + ". No Debian/Ubuntu: sudo apt install wireguard-tools nftables openssh-client iproute2 procps"
        )


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
