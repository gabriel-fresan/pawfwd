"""Execução de comandos remotos na VPS via SSH."""

from __future__ import annotations

import os
import pty
import shlex
import sys

from pawfwd.errors import PawFwdError
from pawfwd.system import run, say


def interactive_ssh(command: list[str]) -> tuple[int, str]:
    """Run SSH attached to a local PTY so SSH and remote sudo can prompt normally."""
    transcript = bytearray()

    def read_and_forward(fd: int) -> bytes:
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if data:
            transcript.extend(data)
        # pty.spawn writes the bytes returned by master_read to our stdout.
        # Writing them here as well duplicated sudo prompts and JSON output.
        return data

    status = pty.spawn(command, master_read=read_and_forward)
    exit_code = os.waitstatus_to_exitcode(status)
    return exit_code, transcript.decode("utf-8", errors="replace")


def ssh_remote(host: str, user: str, port: int, remote_command: list[str]) -> str:
    """Try key/non-interactive SSH first, then fall back to an interactive SSH+sudo session.

    The interactive fallback is intentionally available only from a terminal. It
    does not store passwords or weaken sudoers; remote sudo prompts the user as usual.
    """
    ssh_target = f"{user}@{host}" if user else host
    remote_text = " ".join(shlex.quote(part) for part in remote_command)

    def make_ssh(*, interactive: bool) -> list[str]:
        command = ["ssh"]
        if interactive:
            command.append("-tt")
        command.extend([
            "-p", str(port),
            "-o", f"BatchMode={'no' if interactive else 'yes'}",
            "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new",
            ssh_target, remote_text,
        ])
        # Use the invoking user's SSH keys and known_hosts, not root's files.
        local_user = os.environ.get("SUDO_USER")
        if local_user and local_user != "root":
            command = ["sudo", "-H", "-u", local_user, *command]
        return command

    result = run(make_ssh(interactive=False), check=False)
    if result.returncode == 0:
        return result.stdout.strip()

    details = (result.stderr or result.stdout or "sem detalhes").strip()
    if sys.stdin.isatty() and sys.stdout.isatty():
        say("\n[*] A VPS precisa de autenticação adicional. Abrindo SSH interativo...")
        interactive_command = list(remote_command)
        # The normal path uses sudo -n so automation never hangs. In this
        # terminal-only fallback, remove -n and let sudo display its password prompt.
        if len(interactive_command) >= 2 and interactive_command[:2] == ["sudo", "-n"]:
            interactive_command = ["sudo", *interactive_command[2:]]
        remote_text = " ".join(shlex.quote(part) for part in interactive_command)
        interactive_status, transcript = interactive_ssh(make_ssh(interactive=True))
        if interactive_status == 0:
            return transcript.strip()
        details = transcript.strip() or details

    raise PawFwdError(
        f"Não consegui executar o comando na VPS ({ssh_target}): {details}\n"
        "Em um terminal, o PawFwd permite autenticação SSH e senha sudo interativas. "
        "Sem terminal (por exemplo, em um serviço), configure uma chave SSH e "
        "permissão sudo restrita para os comandos do PawFwd, ou use --ssh-user root."
    )
