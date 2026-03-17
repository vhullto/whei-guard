# Whei Guard — Arquitetura

## Visão Geral

O Whei Guard é uma CLI de análise de segurança que opera em dois domínios distintos: **Web3** (smart contracts Solidity) e **Web2** (source code tradicional — Python, TypeScript, JavaScript, Go, etc.). A ferramenta funciona em duas camadas: um motor estático que detecta suspeitas de vulnerabilidades, e um motor de IA que realiza triagem, elimina falsos positivos e gera relatórios técnicos.

```
┌─────────────────────────────────────────────────────────────┐
│                        whei.py (CLI)                        │
│                  argparse + orquestração                    │
└──────────────┬──────────────────────────┬───────────────────┘
               │                          │
     --target web3                --target web2
               │                          │
    ┌──────────▼──────────┐    ┌──────────▼──────────┐
    │   Slither Engine    │    │   Semgrep Adapter   │
    │  (whei_rules/*.py)  │    │ run_semgrep_adapter  │
    └──────────┬──────────┘    └──────────┬──────────┘
               │                          │
    ┌──────────▼──────────┐    ┌──────────▼──────────┐
    │  exploitability.py  │    │validar_exploitabi-   │
    │  (validador EVM)    │    │lidade_web2()         │
    └──────────┬──────────┘    └──────────┬──────────┘
               │                          │
               └──────────┬───────────────┘
                           │
              Estrutura de finding normalizada
                           │
               ┌───────────▼───────────┐
               │      whei_ai.py       │
               │  Context-Aware AI     │
               │  (Groq / LLM)         │
               └───────────┬───────────┘
                           │
               ┌───────────▼───────────┐
               │    whei_report.py     │
               │  HTML Report Generator│
               └───────────────────────┘
```

---

## Princípios de Engenharia

### Open/Closed Principle (OCP)
A arquitetura é aberta para extensão e fechada para modificação. Adicionar suporte a um novo domínio (ex: Web3 Rust, Mobile) requer apenas:
- Criar um adapter que normalize findings para a estrutura interna
- Adicionar um ramo no `_get_system_prompts()` do `whei_ai.py`
- Adicionar uma entrada em `_DOMAIN_CFG` do `whei_report.py`

O pipeline de IA e o sistema de relatórios não precisam ser modificados.

### Padrão Adapter
O `run_semgrep_adapter()` encapsula toda a integração com o Semgrep e normaliza sua saída para a estrutura interna do Whei Guard. Da mesma forma, o Slither produz findings que são normalizados pelo mesmo formato. O restante do sistema não conhece Slither nem Semgrep — apenas a estrutura de finding.

### Estrutura Normalizada de Finding
Todos os findings, independentemente da origem (Slither ou Semgrep), trafegam no sistema neste formato:

```python
{
    "impact":      "High" | "Medium" | "Low" | "Informational",
    "confidence":  "High" | "Medium" | "Low",
    "check":       "nome-da-regra",
    "description": "mensagem legível",
    "elements": [{
        "type": "function" | "source_code",
        "name": "nome-do-elemento",
        "source_mapping": {
            "filename_absolute": "/abs/path/arquivo",
            "filename_short":    "arquivo.ts",
            "lines":             [10, 11, 12],
        }
    }],
    "raw_source":  "trecho do código afetado",
    "wiki_url":    "https://...",
}
```

---

## Módulos

### `whei.py` — CLI e Orquestrador

Responsabilidades:
- Parsing de argumentos (`argparse`)
- Branching entre Web2 e Web3
- Execução do motor estático correto
- Chamada ao validador de exploitabilidade
- Orquestração das chamadas de IA por finding
- Geração de exportações JSON e HTML

Argumentos principais:

| Argumento | Descrição |
|-----------|-----------|
| `alvo` | Arquivo `.sol`, diretório ou endereço `0x...` |
| `--target` | `web3` (Slither, padrão) ou `web2` (Semgrep) |
| `--ai` | Ativa análise com Groq AI |
| `--model` | Modelo Groq: `scout` (padrão), `versatile`, `qwen` |
| `--semgrep-config` | Config Semgrep: `auto`, `p/owasp-top-ten`, `p/secrets`, etc. |
| `--only` | Filtrar por severidade: `high`, `medium`, `low` |
| `--html` | Exportar relatório HTML |
| `--json` | Exportar findings em JSON |
| `--include-low` | Incluir findings filtrados pelo validador |
| `--no-color` | Desativar cores ANSI |

---

### `whei_ai.py` — Motor de IA Context-Aware

O módulo de IA seleciona prompts de sistema diferentes conforme o domínio, tornando a análise especializada para cada contexto.

**Seleção de prompts:**

```python
def _get_system_prompts(target: str) -> tuple[str, str]:
    if target == "web2":
        return _SYSTEM_FINDING_WEB2, _SYSTEM_EXECUTIVE_WEB2
    return _SYSTEM_FINDING_WEB3, _SYSTEM_EXECUTIVE_WEB3
```

**Web3 — foco EVM:**
- Reentrância (padrão CEI)
- Integer overflow/underflow
- Modificadores de acesso (`onlyOwner`, roles)
- Frontrunning, delegatecall
- Flash loans e oracle manipulation

**Web2 — foco OWASP:**
- OWASP Top 10 (Injection, XSS, IDOR, SSRF, etc.)
- Verificação de sanitização de input no trecho fornecido
- Verificação de middlewares de autenticação/autorização
- Uso de prepared statements vs. queries dinâmicas

**Validador de Exploitabilidade Web2:**

Antes de enviar um finding para a IA, o `validar_exploitabilidade_web2()` aplica 4 heurísticas estáticas para filtrar falsos positivos conhecidos:

1. **Regras de baixo sinal** — regras com alta taxa histórica de FP em frameworks (`gcm-no-tag-length`, `insecure-document-method`)
2. **child_process em CLIs internos** — argumentos em arquivos de tooling que não são expostos via HTTP (`next-info.ts`, `trace-uploader.ts`, etc.)
3. **Bracket notation com constantes importadas** — `req.headers[NEXT_ROUTER_PREFETCH_HEADER]` não é prototype pollution
4. **Argumentos hardcoded** — `spawnSync('git', ['rev-parse', 'HEAD'])` não é user-controlled

**Modelos disponíveis:**

| Chave | Model ID | Tokens/dia | Tokens/min |
|-------|----------|-----------|-----------|
| `scout` | `meta-llama/llama-4-scout-17b-16e-instruct` | 500k | 30k |
| `versatile` | `llama-3.3-70b-versatile` | 100k | 12k |
| `qwen` | `qwen/qwen3-32b` | 500k | 6k |

**Throttle automático:**
Delay configurável entre chamadas (`_GROQ_CALL_DELAY = 2.0s`) para respeitar o rate limit do plano gratuito Groq.

**Saída por finding:**
```json
{
  "titulo": "...",
  "explicacao_tecnica": "...",
  "cenario_exploit": "...",
  "poc_code": "...",
  "como_reproduzir": "...",
  "cvss_score": 9.0,
  "cvss_vetor": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "severidade": "Critical",
  "impacto_financeiro": "...",
  "template_submissao": "...",
  "codigo_corrigido": "..."
}
```

---

### `whei_rules/` — Detectores Web3 (Slither)

Detectores customizados implementados como subclasses de `AbstractDetector` do Slither.

| Arquivo | Argumento | Severidade | O que detecta |
|---------|-----------|-----------|---------------|
| `missing_access_control.py` | `missing-access-control` | 🔴 High | Funções públicas sem modificador de acesso |
| `reentrancy.py` | `reentrancy` | 🔴 High | Chamada externa antes de atualizar estado (CEI) |
| `integer_overflow.py` | `integer-overflow` | 🔴 High | Operação aritmética sem SafeMath em Solidity < 0.8.0 |
| `uninitialized_proxy.py` | `uninitialized-proxy` | 🔴 High | Proxy sem proteção no `initialize()` |
| `oracle_manipulation.py` | `oracle-manipulation` | 🔴 High | Uso de preço spot de DEX como oracle |
| `flash_loan_attack.py` | `flash-loan-attack` | 🔴 High | Callback de flash loan com lógica crítica |
| `unchecked_send.py` | `unchecked-send` | 🟡 Medium | `.send()` / `.call()` sem verificar retorno |
| `tx_origin_auth.py` | `tx-origin-auth` | 🟡 Medium | `tx.origin` para autenticação (phishável) |

**Validador de Exploitabilidade Web3 (`exploitability.py`):**

Filtra findings tecnicamente corretos mas não exploitáveis na prática, economizando tokens de IA:
- Modificadores que restringem acesso (`onlyOwner`, `onlyCeloVM`, etc.)
- Reentrância em funções `initialize` sem fundos em risco
- `tx.origin` em funções `view/pure`
- Funções sem ETH ou variáveis financeiras em risco

---

### `whei_report.py` — Gerador de Relatório HTML

Gera relatório HTML domain-aware com design terminal hacker (dark, monoespaçado).

**Configuração por domínio:**
```python
_DOMAIN_CFG = {
    "web3": {
        "subtitle":   "Smart Contract Security Analyzer",
        "engine":     "Slither",
        "references": "SWC Registry | Slither",
    },
    "web2": {
        "subtitle":   "Enterprise AppSec Analyzer",
        "engine":     "Semgrep",
        "references": "OWASP Top 10 | Semgrep Docs | CWE/MITRE",
    },
}
```

Funcionalidades do HTML gerado:
- Cards de resumo (Total / High / Medium / Low)
- Findings colapsáveis com abertura automática dos High
- Trecho de código com syntax highlighting
- Referências por domínio no rodapé
- Scanline overlay CSS para estética terminal

---

## Fluxo de Execução Web2

```
whei scan ./repo --target web2 --ai --only high --html r.html
        │
        ▼
run_semgrep_adapter(alvo, semgrep_config)
  └─ subprocess: semgrep scan --config <cfg> --json <alvo>
  └─ normaliza JSON → estrutura interna
  └─ deduplica por (check_id, filename)
  └─ lê raw_source do disco se Semgrep não retornou
        │
        ▼
validar_exploitabilidade_web2(finding)
  └─ heurística 1: regra de baixo sinal?  → skip
  └─ heurística 2: CLI interno?           → skip
  └─ heurística 3: constante importada?  → skip
  └─ heurística 4: argumento hardcoded?  → skip
  └─ passou tudo → exploitável
        │
        ▼ (só findings exploitáveis)
analyze_finding(finding, alvo, client, target="web2", model="scout")
  └─ _get_system_prompts("web2") → prompt OWASP
  └─ _extract_source_web2(finding) → lê código real
  └─ _call_groq() com throttle automático
  └─ retorna análise JSON estruturada
        │
        ▼
analyze_executive_summary(findings_ai, client, target="web2")
        │
        ▼
generate_html(target, findings, domain="web2")
```

---

## Fluxo de Execução Web3

```
whei scan contrato.sol --target web3 --ai --html r.html
        │
        ▼
Slither(alvo) → compila contrato
        │
        ▼
sl.register_detector(cls) para cada detector em ALL_DETECTORS
sl.run_detectors() → raw findings
        │
        ▼
validar_exploitabilidade(finding, funcao, contrato)
  └─ verifica modificadores de acesso
  └─ verifica fundos em risco
  └─ verifica padrão CEI
        │
        ▼ (só findings exploitáveis)
analyze_finding(finding, alvo, client, target="web3", model="scout")
  └─ _get_system_prompts("web3") → prompt EVM
  └─ _extract_source_web3(alvo, finding) → lê .sol
  └─ _call_groq() com throttle
        │
        ▼
generate_html(target, findings, domain="web3")
```

---

## Estrutura de Diretórios

```
whei-guard/
├── whei.py                    # CLI principal e orquestrador
├── whei_ai.py                 # Motor de IA (Groq) context-aware
├── whei_report.py             # Gerador de relatório HTML
├── setup.py                   # Instalação como pacote pip
├── requirements.txt           # Dependências
├── .env                       # GROQ_API_KEY (não versionado)
├── .gitignore
├── README.md
├── ARCHITECTURE.md
└── whei_rules/                # Detectores Web3 customizados
    ├── __init__.py            # Registra ALL_DETECTORS
    ├── exploitability.py      # Validador de exploitabilidade Web3
    ├── missing_access_control.py
    ├── reentrancy.py
    ├── integer_overflow.py
    ├── uninitialized_proxy.py
    ├── oracle_manipulation.py
    ├── flash_loan_attack.py
    ├── unchecked_send.py
    └── tx_origin_auth.py
```

---

## Dependências

| Pacote | Uso | Domínio |
|--------|-----|---------|
| `slither-analyzer` | Motor estático de análise de smart contracts | Web3 |
| `semgrep` | Motor estático de análise de source code | Web2 |
| `groq` | Cliente da API Groq para LLM inference | Ambos |
| `solc-select` | Gerenciamento de versões do compilador Solidity | Web3 |

Dependências da stdlib Python usadas: `subprocess`, `json`, `os`, `re`, `time`, `argparse`, `datetime`.

---

## Extensibilidade

### Adicionar um novo detector Web3
1. Criar `whei_rules/novo_detector.py` como subclasse de `AbstractDetector`
2. Importar e adicionar em `whei_rules/__init__.py` na lista `ALL_DETECTORS`
3. Opcionalmente adicionar validador em `exploitability.py`

### Adicionar um novo motor estático (Web2)
1. Criar função `run_<engine>_adapter(alvo) -> list[dict]` em `whei.py`
2. Normalizar saída para a estrutura de finding interna
3. Adicionar opção em `--target` no argparse
4. Adicionar ramo no `cmd_scan`

### Adicionar suporte a novo modelo Groq
1. Adicionar entrada em `GROQ_MODELS` no `whei_ai.py`
2. Adicionar opção em `choices` do `--model` no `whei.py`