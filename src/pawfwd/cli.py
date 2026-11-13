"""Interface de linha de comando."""

from __future__ import annotations

import argparse
import sys

from pawfwd import __version__ as VERSION
from pawfwd.config import load_config, parse_port_spec
from pawfwd.constants import TCP_MSS_DEFAULT, TCP_MSS_MAX, TCP_MSS_MIN
from pawfwd.errors import PawFwdError
from pawfwd.ingress import init_ingress, peer_register
from pawfwd.install import install_command
from pawfwd.reports import cmd_diag, cmd_list, cmd_status
from pawfwd.rules import apply_local, import_rules, sync_rules_to_ingress, update_rules
from pawfwd.system import require_root, say
from pawfwd.target import init_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pawfwd",
        description="PawFwd — encaminhamento de portas com túnel WireGuard dedicado.",
        epilog="Dica: pawfwd add 25505 publica TCP+UDP; use /tcp ou /udp para escolher um só. O ingress aplica MSS clamp TCP automaticamente.",
    )
    parser.add_argument("--version", action="version", version=f"PawFwd {VERSION}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="Inicializa a VPS ou conecta um servidor target")
    init.add_argument("endpoint", nargs="?", help="IP/hostname público da VPS (modo target)")
    init.add_argument("--role", choices=["ingress"], help="Use --role ingress na VPS pública")
    init.add_argument("--listen-port", type=int, default=None, help="Porta UDP WireGuard na VPS (padrão: 51820; escolhe outra se estiver ocupada)")
    init.add_argument("--mss", type=int, default=None, help=f"Limite MSS TCP dos encaminhamentos (padrão: {TCP_MSS_DEFAULT}; faixa {TCP_MSS_MIN}-{TCP_MSS_MAX})")
    init.add_argument("--ssh-host", help="Host usado para SSH; pode ser o nome Tailscale da VPS")
    init.add_argument("--ssh-user", help="Usuário SSH na VPS (padrão: usuário local)")
    init.add_argument("--ssh-port", type=int, default=22, help="Porta SSH da VPS")
    init.add_argument("--name", help="Nome deste peer (padrão: hostname)")

    sub.add_parser("install", help="Instala o executável em /usr/local/bin")
    sub.add_parser("list", aliases=["ls"], help="Lista encaminhamentos")
    sub.add_parser("status", help="Mostra o estado do túnel e dos encaminhamentos")
    sub.add_parser("diag", help="Diagnóstico de rede, WireGuard, rotas e nftables")
    sub.add_parser("apply", help=argparse.SUPPRESS)
    sub.add_parser("sync", help="Sincroniza as regras do target para a VPS")

    add = sub.add_parser("add", help="Adiciona um encaminhamento: PUBLIC[:TARGET][/tcp|/udp]")
    add.add_argument("spec", help="Ex.: 25505, 25505:25565, 19132/udp")
    add.add_argument("--preserve-ip", action="store_true", help="Preserva o IP real do cliente no servidor")

    remove = sub.add_parser("remove", aliases=["rm"], help="Remove um encaminhamento")
    remove.add_argument("spec", help="Ex.: 25505 (remove TCP+UDP) ou 25505/udp")

    peer = sub.add_parser("peer", help=argparse.SUPPRESS)
    peer_sub = peer.add_subparsers(dest="peer_command", required=True)
    register = peer_sub.add_parser("register", help=argparse.SUPPRESS)
    register.add_argument("--public-key", required=True)
    register.add_argument("--name", required=True)

    rules = sub.add_parser("rules", help=argparse.SUPPRESS)
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    imp = rules_sub.add_parser("import", help=argparse.SUPPRESS)
    imp.add_argument("--payload", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        if args.command == "install":
            require_root()
            install_command()
            return 0

        require_root()

        if args.command == "init":
            if args.listen_port is not None and (args.listen_port < 1 or args.listen_port > 65535):
                raise PawFwdError("A porta UDP do WireGuard precisa estar entre 1 e 65535.")
            if args.role == "ingress":
                if args.endpoint:
                    raise PawFwdError("No ingress, não informe endpoint; use 'pawfwd init --role ingress'.")
                init_ingress(args.listen_port, args.mss)
            else:
                if args.mss is not None:
                    raise PawFwdError("--mss só pode ser usado no ingress: pawfwd init --role ingress --mss 1200.")
                if not args.endpoint:
                    raise PawFwdError("Informe o IP público da VPS: 'pawfwd init <IP-DA-VPS>'.")
                init_target(args.endpoint, args.ssh_host, args.ssh_user, args.ssh_port, args.name)
            return 0

        if args.command == "peer":
            if args.peer_command == "register":
                peer_register(args.public_key, args.name)
                return 0

        if args.command == "rules":
            if args.rules_command == "import":
                import_rules(args.payload)
                return 0

        cfg = load_config()
        if args.command in ("list", "ls"):
            cmd_list(cfg)
        elif args.command == "status":
            cmd_status(cfg)
        elif args.command == "diag":
            cmd_diag(cfg)
        elif args.command == "apply":
            apply_local(cfg)
        elif args.command == "sync":
            if cfg["role"] != "target":
                raise PawFwdError("Execute 'sync' no target, que envia as regras para a VPS.")
            apply_local(cfg)
            sync_rules_to_ingress(cfg)
            say("[+] Sincronização concluída. Tudo no trilho. :3")
        elif args.command == "add":
            spec = parse_port_spec(args.spec)
            update_rules(cfg, spec, remove=False, preserve_ip=args.preserve_ip)
        elif args.command in ("remove", "rm"):
            spec = parse_port_spec(args.spec)
            update_rules(cfg, spec, remove=True)
        else:
            parser.error("comando inválido")
        return 0
    except PawFwdError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[*] Interrompido. O PawFwd continua no estado anterior.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
