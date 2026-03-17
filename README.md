<div align="center">

```
 ██╗    ██╗██╗  ██╗███████╗██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██║    ██║██║  ██║██╔════╝██║    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██║ █╗ ██║███████║█████╗  ██║    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║███╗██║██╔══██║██╔══╝  ██║    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚███╔███╔╝██║  ██║███████╗██║    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**Enterprise AppSec Analyzer — Web2 + Web3**

*Análise estática + triagem por IA em um único comando*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Semgrep](https://img.shields.io/badge/engine-Semgrep-orange)
![Slither](https://img.shields.io/badge/engine-Slither-purple)
![Groq](https://img.shields.io/badge/AI-Groq%20LLM-red)

</div>

---

## O que é

Whei Guard é uma CLI de análise de segurança que combina motores estáticos com triagem por IA para identificar vulnerabilidades reais em repositórios de código e smart contracts. Funciona em dois modos:

- **Web3** — Analisa contratos Solidity com detectores customizados sobre o Slither. Detecta reentrância, missing access control, integer overflow, flash loan vectors, oracle manipulation e outros padrões críticos de EVM.
- **Web2** — Analisa repositórios de código com Semgrep. Suporta Python, TypeScript, JavaScript, Go, Java e qualquer linguagem reconhecida pelo Semgrep.

Em ambos os modos, um motor de IA (Groq) recebe o código-fonte afetado e a regra violada para triagem de falsos positivos, geração de PoC, CVSS e template de submissão para bug bounty.

---

## Instalação

### Pré-requisitos

- Python 3.10+
- Para Web3: `solc-select` e compilador Solidity
- Para Web2: `semgrep`
- Chave de API da [Groq](https://console.groq.com) (gratuita)

### Setup

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/whei-guard.git
cd whei-guard

# 2. Crie o ambiente virtual
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# 3. Instale as dependências
pip install -e .

# 4. Instale o Semgrep (para Web2)
pipx install semgrep        # recomendado no Arch/Linux
# pip install semgrep       # alternativa

# 5. Instale o compilador Solidity (para Web3)
pip install solc-select
solc-select install 0.8.0
solc-select use 0.8.0

# 6. Configure a API key do Groq
echo "GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx" > .env
```

### Verificação

```bash
whei --help
semgrep --version   # Web2
slither --version   # Web3
```

---

## Uso

### Web2 — Análise de repositório

```bash
# Scan básico (sem IA)
whei scan ./meu-repo --target web2

# Com IA, só High, exporta HTML
whei scan ./meu-repo --target web2 --ai --only high --html relatorio.html

# Config focada em OWASP Top 10 (menos ruído que auto)
whei scan ./meu-repo --target web2 --semgrep-config p/owasp-top-ten --ai --only high

# Busca por segredos expostos
whei scan ./meu-repo --target web2 --semgrep-config p/secrets --ai

# Exporta JSON e HTML
whei scan ./meu-repo --target web2 --ai --json out.json --html relatorio.html
```

### Web3 — Análise de smart contracts

```bash
# Scan básico
whei scan contrato.sol

# Com IA
whei scan contrato.sol --ai

# Diretório inteiro, só High, com relatório
whei scan ./contracts --only high --ai --html relatorio.html

# Ver todos os findings incluindo baixo risco
whei scan contrato.sol --include-low

# Listar detectores disponíveis
whei list
```

### Opções de modelo

```bash
# scout — padrão, 500k tokens/dia (llama-4-scout)
whei scan ./repo --target web2 --ai --model scout

# versatile — mais capaz, 100k tokens/dia (llama-3.3-70b)
whei scan ./repo --target web2 --ai --model versatile

# qwen — 500k tokens/dia (qwen3-32b)
whei scan ./repo --target web2 --ai --model qwen
```

---

## Configurações Semgrep recomendadas

| Config | Quando usar |
|--------|-------------|
| `auto` | Scan geral — detecta linguagem automaticamente. Gera mais ruído. |
| `p/owasp-top-ten` | Foco em vulnerabilidades OWASP. Menos ruído, mais relevante. |
| `p/secrets` | Busca por API keys, tokens e credenciais expostas. |
| `p/javascript` | Regras específicas para JS/TS. |
| `p/python` | Regras específicas para Python. |
| `p/docker` | Misconfigs em Dockerfiles. |

---

## Saída

### Terminal

```
[1] 🔴  HIGH  javascript.lang.security.detect-child-process  (confiança: High)
  ⚡ EXPLOITAVEL  Nenhuma heurística de falso positivo acionada

  Detected calls to child_process from a function argument `query`.
  This could lead to a command injection if the input is user controllable.

  Elementos afetados:
    [source_code] → upgrade.ts:46

  Trecho:
    const result = exec(query)

  ✦ ANALISE IA
  CVSS: 9.0  Critical  AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

  -- RISCO TECNICO
  ...
  -- CENARIO DE EXPLOIT
  ...
  -- POC
  ...
  -- FIX SUGERIDO
  ...
```

### Relatório HTML

Relatório interativo com design terminal hacker gerado com `--html`:
- Cards de resumo por severidade
- Findings colapsáveis com abertura automática dos High
- Trecho de código do finding
- Análise completa da IA por finding
- Referências OWASP / SWC Registry no rodapé

---

## Detectores Web3

| Detector | Severidade | O que detecta |
|----------|-----------|---------------|
| `missing-access-control` | 🔴 High | Funções públicas sem modificador de acesso |
| `reentrancy` | 🔴 High | Chamada externa antes de atualizar estado (CEI) |
| `integer-overflow` | 🔴 High | Operação aritmética sem SafeMath em Solidity < 0.8.0 |
| `uninitialized-proxy` | 🔴 High | Proxy upgradeable com `initialize()` desprotegido |
| `oracle-manipulation` | 🔴 High | Uso de preço spot de DEX como oracle |
| `flash-loan-attack` | 🔴 High | Callback de flash loan com lógica crítica sem guard |
| `unchecked-send` | 🟡 Medium | `.send()` / `.call()` sem verificar retorno |
| `tx-origin-auth` | 🟡 Medium | `tx.origin` para autenticação (phishável) |

---

## Arquitetura

Veja [ARCHITECTURE.md](ARCHITECTURE.md) para documentação técnica completa, incluindo:
- Diagrama de fluxo de execução
- Princípios de engenharia (OCP, Adapter Pattern)
- Estrutura normalizada de findings
- Como estender com novos detectores e motores

---

## Variáveis de ambiente

| Variável | Obrigatória | Descrição |
|----------|-------------|-----------|
| `GROQ_API_KEY` | Sim (com `--ai`) | Chave da API Groq. Lida do `.env` ou da variável de ambiente. |

---

## Limites do plano gratuito Groq

| Modelo | Tokens/dia | Tokens/min | Recomendado para |
|--------|-----------|-----------|-----------------|
| `scout` (padrão) | 500k | 30k | Repositórios grandes |
| `versatile` | 100k | 12k | Análise mais profunda |
| `qwen` | 500k | 6k | Alternativa ao scout |

A ferramenta aplica throttle automático de 2s entre chamadas para respeitar os limites do plano gratuito.

---

## Contribuindo

1. Fork o repositório
2. Crie uma branch: `git checkout -b feat/novo-detector`
3. Para novos detectores Web3, veja a estrutura em `whei_rules/reentrancy.py` como referência
4. Para novas heurísticas Web2, adicione em `validar_exploitabilidade_web2()` no `whei_ai.py`
5. Abra um Pull Request

---

## Referências

- [Slither](https://github.com/crytic/slither) — Static analyzer for Solidity
- [Semgrep](https://semgrep.dev) — Static analysis for 30+ languages
- [SWC Registry](https://swcregistry.io) — Smart Contract Weakness Classification
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — Web application security risks
- [Groq](https://console.groq.com) — LLM inference API
- [Immunefi](https://immunefi.com) — Web3 bug bounty platform

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.