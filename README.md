# PawFwd

**P**ackets **A**cross **W**ireGuard, **F**orwarded.

O PawFwd publica serviços que rodam em uma rede doméstica (sem IP público ou atrás de CGNAT) por meio de uma VPS com IP público. O tráfego entra pela VPS, atravessa um túnel WireGuard dedicado e chega ao servidor de casa.

```
cliente ──► VPS (ingress, IP público)
                 │  DNAT + MSS clamp
                 ▼
          túnel WireGuard dedicado  (10.77.0.0/24)
                 │
                 ▼
          servidor doméstico (target)
```

O Tailscale, se já estiver instalado, não é alterado. O PawFwd usa uma interface WireGuard própria e deixa o SSH e a administração no Tailscale.

## Recursos

- Encaminhamento TCP, UDP ou ambos, com porta pública e porta de destino diferentes.
- Clamp de MSS TCP no ingress, configurável (padrão 1200).
- Opção `--preserve-ip` para o serviço enxergar o IP real do cliente, via policy routing.
- Detecção de conflitos de sub-rede e de porta UDP.
- Limpeza automática de instalações antigas (VXLAN e a v2 de transição).

## Requisitos

- Linux com systemd e acesso root.
- Python 3.10 ou superior.
- `wireguard-tools`, `nftables`, `openssh-client`, `iproute2` e `procps`.
  No Debian/Ubuntu: `sudo apt install wireguard-tools nftables openssh-client iproute2 procps`
- Na VPS, a porta UDP do WireGuard (padrão 51820) liberada no firewall do provedor.

## Instalação

Recomendamos um ambiente virtual dedicado. O launcher gravado em `/usr/local/bin/pawfwd` usa o Python desse ambiente, então o root precisa conseguir lê-lo.

```bash
sudo python3 -m venv /opt/pawfwd
sudo /opt/pawfwd/bin/pip install /caminho/para/pawfwd
sudo /opt/pawfwd/bin/pawfwd init --role ingress   # na VPS
```

## Uso

### 1. Configurar a VPS (ingress)

```bash
sudo pawfwd init --role ingress
# opcional: --listen-port 51820 --mss 1200
```

A chave pública impressa no final é usada no passo seguinte.

### 2. Conectar o servidor doméstico (target)

```bash
sudo pawfwd init <IP-PUBLICO-DA-VPS> --ssh-host <HOST-SSH-DA-VPS> --name meu-servidor
```

O target registra a própria chave na VPS via SSH. Se a VPS pedir senha, o `sudo` interativo é usado no terminal; em serviços, configure chave SSH e uma regra de sudo restrita.

### 3. Gerenciar encaminhamentos (a partir do target)

```bash
sudo pawfwd add 25505                 # TCP e UDP, mesma porta
sudo pawfwd add 25505:25565/tcp       # porta pública 25505 → destino 25565, só TCP
sudo pawfwd add 19132/udp --preserve-ip
sudo pawfwd remove 25505/udp
sudo pawfwd list
sudo pawfwd status
sudo pawfwd diag                      # diagnóstico de rede, WireGuard e nftables
```

Cada alteração é salva em `/etc/paw-fwd/config.json`, aplicada localmente e sincronizada com a VPS.

## Nomes de sistema

O nome do projeto e o comando são `pawfwd`. Alguns identificadores de sistema continuam com o nome antigo `paw-fwd` para não derrubar instalações em execução:

| Recurso | Nome |
|---|---|
| Comando | `pawfwd` |
| Configuração | `/etc/paw-fwd/config.json` |
| Interface WireGuard | `paw-fwd` |
| Unidades systemd | `paw-fwd.service`, `wg-quick@paw-fwd.service` |
| Tabelas nftables | `paw_fwd`, `paw_fwd_mss`, `paw_fwd_target` |

Renomear esses itens exige migração coordenada entre VPS e servidor doméstico e está planejado para uma versão futura.

## Desenvolvimento

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
```

Os testes cobrem as funções puras (parsing, validação, configuração WireGuard, MSS e registro de peers). Comandos que alteram rede, nftables e systemd precisam de um ambiente Linux com root e são testados manualmente.

## Licença

Ainda não definida.
