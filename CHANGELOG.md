# Changelog

Todas as mudanças notáveis deste projeto estão documentadas aqui.
O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [Não lançado]

### Alterado
- O código foi separado do script único em um pacote Python (`src/pawfwd`), organizado por responsabilidade.
- O comando passou de `paw-fwd` para `pawfwd`. Os nomes de sistema (interface, unidades systemd, `/etc/paw-fwd`, tabelas nftables) foram mantidos.
- Projeto empacotado com `pyproject.toml` e entry point `pawfwd`.

### Corrigido
- `pawfwd install` e `pawfwd init` gravam um launcher em `/usr/local/bin/pawfwd` em vez de copiar o próprio módulo, que deixaria de funcionar após a separação em pacote.

### Adicionado
- Licença MIT, CONTRIBUTING, SECURITY e workflow de CI (lint, formatação e testes em Python 3.10, 3.12 e 3.13).
- README em inglês com tradução em português (`README.pt-BR.md`).
- Testes unitários para parsing de portas, validação de regras e MSS, configuração WireGuard, registro de peers e instalação do launcher.
- README e CHANGELOG.

## [2.2.0]

- Versão inicial em script único, com suporte a ingress e target, DNAT, MSS clamp TCP, `--preserve-ip` e limpeza de instalações antigas.
