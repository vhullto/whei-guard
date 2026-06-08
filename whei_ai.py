"""
whei_ai.py — Módulo de integração com AI providers para análise de segurança.

Context-Aware: seleciona prompts de sistema conforme o domínio.
  - web3: EVM, Reentrância, CEI, modificadores, flash loans.
  - web2: OWASP Top 10, Injeções, IDOR, XSS, autenticação, sanitização.

Produz por finding: explicação técnica, exploit, CVSS, PoC, fix e template.
Produz no final: resumo executivo consolidado.

Providers suportados:
  - groq      (padrão, gratuito, GROQ_API_KEY)
  - anthropic (pago, mais capaz, ANTHROPIC_API_KEY)
  - deepseek  (custo baixo, chain-of-thought, DEEPSEEK_API_KEY)

Fallback chain: deepseek → groq → offline (acionado automaticamente em caso
de falha de inicialização do provider primário).
"""

import os
import re
import json
import time

# ══════════════════════════════════════════════════════════════════════════════
#  Validador de exploitabilidade Web2
#  Analogia ao exploitability.py do Web3 — filtra falsos positivos conhecidos
#  antes de enviar para a IA, economizando tokens.
# ══════════════════════════════════════════════════════════════════════════════

# Padrões de argumentos que indicam valor hardcoded (não user-controlled)
_HARDCODED_ARG_PATTERNS = [
    r"'[a-z_\-]+(?:\.[a-z]+)?'",   # string literal: 'git', 'ls', 'HEAD'
    r'"[a-z_\-]+(?:\.[a-z]+)?"',   # string literal com aspas duplas
    r'os\.platform',            # os.platform() — não é input do usuário
    r'process\.env',            # variável de ambiente
    r'__dirname',               # constante Node.js
    r'__filename',              # constante Node.js
]

# Nomes de constantes importadas comuns no Next.js que não são user-controlled
_KNOWN_CONSTANTS = {
    "NEXT_ROUTER_SEGMENT_PREFETCH_HEADER",
    "NEXT_ROUTER_PREFETCH_HEADER",
    "NEXT_ROUTER_STATE_TREE_HEADER",
    "RSC_HEADER", "NEXT_URL", "NEXT_RSC_UNION_QUERY",
    "MATCHED_PATH_HEADER", "HTML_CONTENT_TYPE_HEADER",
    "JSON_CONTENT_TYPE_HEADER", "NEXT_RESUME_HEADER",
}

# Regras Semgrep que tipicamente geram falsos positivos em frameworks maduros
_LOW_SIGNAL_RULES = {
    # innerHTML em frameworks — geralmente controlado internamente
    "javascript.browser.security.insecure-document-method.insecure-document-method",
    # Crypto com GCM — regra não entende setAuthTag como alternativa válida
    "javascript.node-crypto.security.gcm-no-tag-length.gcm-no-tag-length",
}

# child_process em contextos que são CLIs internos, não request handlers
_CLI_TOOL_PATTERNS = [
    "next-info", "next-upgrade", "next-telemetry",
    "trace-uploader", "get-registry", "start-server",
    "upgrade.ts", "pack-util", "next-info.ts",
]


def validar_exploitabilidade_web2(finding: dict) -> dict:
    """
    Valida estaticamente se um finding Web2 é exploitável na prática.
    Retorna dict com: exploitavel, razao, skip.

    Heurísticas aplicadas:
    1. Regra de baixo sinal → skip
    2. child_process em arquivo de CLI interno → skip
    3. bracket notation com constante conhecida → skip
    4. child_process com argumento literal/hardcoded → skip
    """
    check_id   = finding.get("check", "")
    raw_source = finding.get("raw_source", "")
    elements   = finding.get("elements", [])

    filename = ""
    for el in elements:
        filename = el.get("source_mapping", {}).get("filename_short",
                   el.get("source_mapping", {}).get("filename_absolute", ""))
        if filename:
            break

    # Heurística 1: regra de baixo sinal conhecida
    if check_id in _LOW_SIGNAL_RULES:
        return {
            "exploitavel": False,
            "razao": f"Regra '{check_id}' tem alta taxa de falso positivo em frameworks",
            "skip": True,
        }

    # Heurística 2: child_process em arquivo de CLI/tooling interno
    if "child_process" in check_id or "spawn" in check_id:
        filename_lower = filename.lower()
        for pattern in _CLI_TOOL_PATTERNS:
            if pattern in filename_lower:
                return {
                    "exploitavel": False,
                    "razao": f"child_process em CLI/tooling interno ({filename}) — não exposto via HTTP",
                    "skip": True,
                }

    # Heurística 3: bracket notation com constante conhecida importada
    if "remote-property-injection" in check_id or "bracket" in check_id:
        if raw_source:
            for const in _KNOWN_CONSTANTS:
                if const in raw_source:
                    return {
                        "exploitavel": False,
                        "razao": f"Bracket notation usa constante importada '{const}', não input do usuário",
                        "skip": True,
                    }

    # Heurística 4: child_process com argumento aparentemente hardcoded
    if "child_process" in check_id or "spawn" in check_id:
        if raw_source:
            import re as _re
            for pattern in _HARDCODED_ARG_PATTERNS:
                if _re.search(pattern, raw_source):
                    # Só pula se o argumento dinâmico NÃO aparecer junto
                    # (heurística conservadora — mantém dúvida se há ambos)
                    if "req." not in raw_source and "query." not in raw_source                        and "params." not in raw_source and "body." not in raw_source                        and "input" not in raw_source.lower():
                        return {
                            "exploitavel": False,
                            "razao": "Argumento do child_process parece ser valor hardcoded, não input de usuário",
                            "skip": True,
                        }

    # Passou em todas as heurísticas — tratar como exploitável
    return {
        "exploitavel": True,
        "razao": "Nenhuma heurística de falso positivo acionada — análise manual recomendada",
        "skip": False,
    }


# ── Modelos disponíveis ──────────────────────────────────────────────────────
# Groq — chave usada em --model quando --provider groq (padrão)
GROQ_MODELS = {
    "scout":     "meta-llama/llama-4-scout-17b-16e-instruct",  # 500k TPD, 30k TPM — padrão
    "versatile": "llama-3.3-70b-versatile",                    # 100k TPD, 12k TPM — mais capaz
    "qwen":      "qwen/qwen3-32b",                             # 500k TPD, 6k TPM
}
DEFAULT_MODEL = "scout"

# Anthropic — chave usada em --model quando --provider anthropic
ANTHROPIC_MODELS = {
    "sonnet":  "claude-sonnet-4-5",   # Melhor custo-benefício — recomendado
    "haiku":   "claude-haiku-4-5",    # Mais rápido e barato
}
DEFAULT_ANTHROPIC_MODEL = "sonnet"

# DeepSeek — chave usada em --model quando --provider deepseek
DEEPSEEK_MODELS = {
    "chat":     "deepseek-chat",      # Rápido, suporta JSON mode, bom para triagem SAST
    "reasoner": "deepseek-reasoner",  # Chain-of-thought interno, melhor qualidade, sem JSON mode
}
DEFAULT_DEEPSEEK_MODEL = "chat"

_DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

# Intervalo mínimo entre chamadas à API Groq (segundos).
# O plano gratuito permite ~30 req/min → 2s de margem segura.
_GROQ_CALL_DELAY = 2.0
_last_groq_call: float = 0.0

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class _DeepSeekClient:
    """Lightweight wrapper that carries the DeepSeek API key."""
    def __init__(self, api_key: str):
        self.api_key = api_key


# ═══════════════════════════════════════════════════════════════════════════════
#  Prompts de sistema — separados por domínio
#  Princípio OCP: adicionar domínio = adicionar constantes + ramo em
#  _get_system_prompts(). Nenhuma outra função é alterada.
# ═══════════════════════════════════════════════════════════════════════════════

_SYSTEM_FINDING_WEB3 = """Voce e um auditor senior de smart contracts especializado em bug bounty Web3.
Analise APENAS a vulnerabilidade descrita abaixo - nao misture com outros findings.
Foque em vulnerabilidades da EVM: Reentrancia (padrao CEI), overflow/underflow,
modificadores de acesso (onlyOwner, roles), frontrunning, delegatecall, flash loans e oracle manipulation.
Produza um relatorio tecnico completo para submissao em Immunefi, Code4rena ou HackerOne.

REGRAS OBRIGATORIAS:
- Responda SEMPRE em portugues brasileiro
- Analise SOMENTE a funcao e o detector informados
- Retorne APENAS um objeto JSON valido e completo
- O JSON deve comecar IMEDIATAMENTE com { sem nenhum espaco, newline ou texto antes
- Nao use markdown, nao use blocos de codigo, nao use prefixos
- Nunca use aspas simples dentro de valores string
- Nunca use barras invertidas desnecessarias"""

_SYSTEM_FINDING_WEB2 = """Voce e um engenheiro senior de Application Security (AppSec) especializado em auditoria de codigo Web2.
Analise APENAS a vulnerabilidade descrita abaixo - nao misture com outros findings.
Foque em vulnerabilidades OWASP Top 10: SQL Injection, Command Injection, XSS, IDOR, SSRF,
Broken Authentication, Insecure Deserialization e Broken Access Control.
No trecho de codigo fornecido, verifique explicitamente:
  - Existe sanitizacao ou validacao de input?
  - Ha middlewares de autenticacao/autorizacao protegendo o endpoint?
  - O ORM ou driver de banco usa prepared statements ou query parametrizada?
Produza um relatorio tecnico completo adequado para programas de bug bounty corporativos.

REGRAS OBRIGATORIAS:
- Responda SEMPRE em portugues brasileiro
- Analise SOMENTE a vulnerabilidade e o trecho de codigo informados
- Retorne APENAS um objeto JSON valido e completo
- O JSON deve comecar IMEDIATAMENTE com { sem nenhum espaco, newline ou texto antes
- Nao use markdown, nao use blocos de codigo, nao use prefixos
- Nunca use aspas simples dentro de valores string
- Nunca use barras invertidas desnecessarias"""

_SYSTEM_EXECUTIVE_WEB3 = """Voce e um auditor-chefe de seguranca Web3 preparando relatorio executivo para bug bounty.
Responda em portugues brasileiro.
Retorne APENAS um objeto JSON valido comecando IMEDIATAMENTE com { sem texto antes.
Sem markdown, sem blocos de codigo, sem prefixos."""

_SYSTEM_EXECUTIVE_WEB2 = """Voce e um CISO / Lead AppSec Engineer preparando relatorio executivo de seguranca corporativa.
Avalie os findings sob a perspectiva OWASP e risco de negocio.
Priorize vetores com maior impacto operacional: RCE, vazamento de dados, escalada de privilegio.
Responda em portugues brasileiro.
Retorne APENAS um objeto JSON valido comecando IMEDIATAMENTE com { sem texto antes.
Sem markdown, sem blocos de codigo, sem prefixos."""


def _get_system_prompts(target: str) -> tuple:
    """Retorna (finding_system, executive_system) para o domínio informado."""
    if target == "web2":
        return _SYSTEM_FINDING_WEB2, _SYSTEM_EXECUTIVE_WEB2
    return _SYSTEM_FINDING_WEB3, _SYSTEM_EXECUTIVE_WEB3


# ═══════════════════════════════════════════════════════════════════════════════
#  Prompts de usuário
# ═══════════════════════════════════════════════════════════════════════════════

_USER_FINDING_WEB3 = """Retorne SOMENTE um objeto JSON (comecando com {{ e terminando com }}) com estas chaves:

{{
  "titulo": "titulo conciso e especifico para esta funcao",
  "explicacao_tecnica": "explicacao tecnica do risco especifico desta funcao na EVM",
  "cenario_exploit": "passo a passo de como explorar esta funcao vulneravel on-chain",
  "poc_code": "codigo Solidity de exploit para esta funcao especifica",
  "como_reproduzir": "passos com Foundry ou Hardhat para testar esta vulnerabilidade",
  "cvss_score": 8.5,
  "cvss_vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "severidade": "High",
  "impacto_financeiro": "descricao do impacto financeiro especifico (perda de fundos, dreno de pool, etc.)",
  "template_submissao": "texto completo para submeter no bug bounty",
  "codigo_corrigido": "codigo desta funcao reescrito de forma segura usando boas praticas EVM"
}}

ALVO:
- Contrato: {alvo}
- Detector: {detector}
- Funcao: {funcao}
- Severidade: {impacto}
- Confianca: {confianca}

Descricao:
{descricao}

Codigo-fonte relevante:
{trecho_fonte}"""

_USER_FINDING_WEB2 = """Retorne SOMENTE um objeto JSON (comecando com {{ e terminando com }}) com estas chaves:

{{
  "titulo": "titulo conciso descrevendo a classe da vulnerabilidade e o local afetado",
  "explicacao_tecnica": "explicacao tecnica do risco, indicando se ha sanitizacao, autenticacao ou prepared statements no trecho analisado",
  "cenario_exploit": "passo a passo de como explorar esta vulnerabilidade (payload, curl, ferramenta)",
  "poc_code": "payload ou script de exploit (curl, Python requests, etc.) especifico para este caso",
  "como_reproduzir": "passos detalhados para reproduzir localmente ou em ambiente de staging",
  "cvss_score": 7.5,
  "cvss_vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "severidade": "High",
  "impacto_financeiro": "impacto para o negocio: vazamento de dados, RCE, acesso indevido, compliance, etc.",
  "template_submissao": "texto completo para submeter no programa de bug bounty corporativo",
  "codigo_corrigido": "trecho de codigo corrigido com sanitizacao, validacao ou controle de acesso adequado"
}}

ALVO:
- Arquivo/Servico: {alvo}
- Regra Semgrep: {detector}
- Elemento: {funcao}
- Severidade: {impacto}
- Confianca: {confianca}

Descricao da vulnerabilidade:
{descricao}

Trecho de codigo afetado:
{trecho_fonte}"""

_USER_EXECUTIVE = """Retorne SOMENTE um objeto JSON (comecando com {{ e terminando com }}) com estas chaves:

{{
  "resumo_geral": "paragrafo executivo de 3-4 frases sobre o estado de seguranca do sistema auditado",
  "risco_geral": "Critical",
  "score_seguranca": 20,
  "vetor_principal": "qual e o vetor de ataque mais critico identificado",
  "findings_priorizados": [
    {{"titulo": "titulo do finding", "prioridade": 1, "razao": "por que corrigir/reportar primeiro"}}
  ],
  "recomendacoes_imediatas": ["acao 1", "acao 2"],
  "estrategia_submissao": "como priorizar submissoes ou remediacao para maximizar impacto",
  "total_critical": 0,
  "total_high": 0,
  "total_medium": 0,
  "total_low": 0
}}

Findings ({total} total):
{findings_json}"""


# ═══════════════════════════════════════════════════════════════════════════════
#  Sanitização de JSON
# ═══════════════════════════════════════════════════════════════════════════════

def _sanitize_json(raw: str) -> str:
    raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    raw = re.sub(r"\s*```$", "", raw.strip())
    raw = raw.replace("\\'", "'")

    def clean(s: str) -> str:
        out = []
        in_str = False
        esc = False
        for ch in s:
            if esc:
                out.append(ch)
                esc = False
                continue
            if ch == "\\":
                esc = True
                out.append(ch)
                continue
            if ch == '"':
                in_str = not in_str
            if in_str and ord(ch) < 32 and ch not in ("\n", "\t", "\r"):
                out.append(" ")
            else:
                out.append(ch)
        return "".join(out)

    return clean(raw)


def _parse_json_robust(raw: str) -> dict:
    """Tenta parsear JSON com 4 níveis de fallback."""
    raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    sanitized = _sanitize_json(raw)
    try:
        return json.loads(sanitized)
    except json.JSONDecodeError:
        pass

    start = raw.find("{")
    if start >= 0:
        try:
            return json.loads(raw[start:])
        except json.JSONDecodeError:
            pass

    match = re.search(r"\{.*\}", sanitized, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return {
        "erro": "Nao foi possivel parsear a resposta como JSON.",
        "preview": raw[:400],
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Clientes — Groq e Anthropic
# ═══════════════════════════════════════════════════════════════════════════════

def _load_env_key(key_name: str) -> str | None:
    """Lê uma chave do ambiente ou do arquivo .env."""
    value = os.environ.get(key_name)
    if value:
        return value
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith(f"{key_name}="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def _get_client(provider: str = "groq"):
    """
    Retorna o cliente de IA configurado para o provider informado.

    Args:
        provider: "groq" (padrão), "anthropic" ou "deepseek"

    Returns:
        Tupla (client, provider_name) para uso em _call_ai()
    """
    if provider == "anthropic":
        if not ANTHROPIC_AVAILABLE:
            raise RuntimeError(
                "Pacote anthropic nao instalado. Execute: pip install anthropic"
            )
        api_key = _load_env_key("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY nao encontrada.\n"
                "Adicione ao .env:\n"
                "  ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx"
            )
        return anthropic.Anthropic(api_key=api_key), "anthropic"

    if provider == "deepseek":
        try:
            import requests as _r
            _ = _r  # verify import succeeds
        except ImportError:
            raise RuntimeError(
                "Pacote requests nao instalado (necessario para DeepSeek).\n"
                "Execute: pip install requests"
            )
        api_key = _load_env_key("DEEPSEEK_API_KEY")
        if not api_key:
            raise RuntimeError(
                "DEEPSEEK_API_KEY nao encontrada.\n"
                "Adicione ao .env:\n"
                "  DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx\n"
                "Obtenha em: https://platform.deepseek.com/api_keys"
            )
        return _DeepSeekClient(api_key), "deepseek"

    # Groq (padrão)
    if not GROQ_AVAILABLE:
        raise RuntimeError("Pacote groq nao instalado. Execute: pip install groq")
    api_key = _load_env_key("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY nao encontrada.\n"
            "Crie um arquivo .env com:\n"
            "  GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx"
        )
    return Groq(api_key=api_key), "groq"


def _get_client_with_fallback(provider: str = "groq"):
    """
    Tenta inicializar o provider solicitado; faz fallback para a cadeia
    deepseek → groq se o provider primário falhar.

    Returns:
        Tupla (client, actual_provider_name)

    Raises:
        RuntimeError se todos os providers da cadeia falharem.
    """
    # Cadeia de fallback: provider solicitado primeiro, depois alternativas
    chain = [provider]
    if provider == "deepseek" and "groq" not in chain:
        chain.append("groq")
    elif provider == "groq" and "deepseek" not in chain:
        chain.append("deepseek")

    last_exc = None
    for p in chain:
        try:
            client, actual = _get_client(p)
            if p != provider:
                import sys as _sys
                print(
                    f"\n  \033[93m[!] Provider '{provider}' indisponivel — "
                    f"usando fallback '{actual}'\033[0m",
                    file=_sys.stderr,
                )
            return client, actual
        except Exception as exc:
            last_exc = exc
            continue

    raise RuntimeError(
        f"Todos os providers falharam. Ultimo erro: {last_exc}"
    )


def _call_groq(client, system: str, user: str, model: str = None) -> dict:
    """
    Chamada à API Groq com parse robusto e throttle automático.
    Mantido para compatibilidade — internamente delega a _call_ai().
    """
    return _call_ai(client, "groq", system, user, model=model)


def _call_anthropic(client, system: str, user: str, model: str = None) -> dict:
    """Chamada à API Anthropic com parse robusto."""
    return _call_ai(client, "anthropic", system, user, model=model)


def _call_ai(client, provider: str, system: str, user: str, model: str = None) -> dict:
    """
    Chamada unificada de IA com throttle (Groq) e parse robusto.

    Args:
        client:   instância do cliente (Groq ou anthropic.Anthropic)
        provider: "groq" | "anthropic"
        system:   prompt de sistema
        user:     prompt de usuário
        model:    model ID ou chave do dicionário de modelos
    """
    global _last_groq_call

    if provider == "groq":
        # Throttle apenas para Groq (rate limit do plano gratuito)
        elapsed = time.monotonic() - _last_groq_call
        if elapsed < _GROQ_CALL_DELAY:
            time.sleep(_GROQ_CALL_DELAY - elapsed)

    try:
        if provider == "anthropic":
            resolved_model = (
                ANTHROPIC_MODELS.get(model, model)
                if model and model in ANTHROPIC_MODELS
                else ANTHROPIC_MODELS[DEFAULT_ANTHROPIC_MODEL]
            )
            response = client.messages.create(
                model=resolved_model,
                max_tokens=4096,
                temperature=0.1,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            raw = response.content[0].text

        elif provider == "deepseek":
            import requests as _req
            resolved_model = (
                DEEPSEEK_MODELS.get(model, model)
                if model and model in DEEPSEEK_MODELS
                else DEEPSEEK_MODELS[DEFAULT_DEEPSEEK_MODEL]
            )
            payload: dict = {
                "model":    resolved_model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
                "temperature": 0.1,
                "max_tokens":  8000,
            }
            # deepseek-chat supports JSON mode; deepseek-reasoner uses CoT internally
            # and does not support response_format
            if resolved_model == "deepseek-chat":
                payload["response_format"] = {"type": "json_object"}

            headers = {
                "Authorization": f"Bearer {client.api_key}",
                "Content-Type":  "application/json",
            }
            resp = _req.post(
                _DEEPSEEK_API_URL,
                headers=headers,
                json=payload,
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            raw  = data["choices"][0]["message"]["content"]

        else:  # groq
            resolved_model = model or GROQ_MODELS[DEFAULT_MODEL]
            response = client.chat.completions.create(
                model=resolved_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
                temperature=0.1,
                max_tokens=4096,
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content

        return _parse_json_robust(raw)

    except Exception as exc:
        return {"erro": str(exc)}
    finally:
        if provider == "groq":
            _last_groq_call = time.monotonic()


# ═══════════════════════════════════════════════════════════════════════════════
#  Extração de código-fonte
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_element_name(finding: dict) -> str:
    """Tenta extrair o nome da função/elemento afetado."""
    elements = finding.get("elements", [])
    for el in elements:
        if el.get("type") == "function":
            return el.get("name", "desconhecida")
    desc = finding.get("description", "")
    match = re.search(r"(\w+\.\w+\([^)]*\))", desc)
    if match:
        return match.group(1)
    return "desconhecida"


def _extract_source_web3(alvo: str, finding: dict) -> str:
    """Extrai trecho Solidity via source_mapping do Slither."""
    elements    = finding.get("elements", [])
    lines_range = []
    for el in elements:
        lns = el.get("source_mapping", {}).get("lines", [])
        lines_range.extend(lns)

    arquivo_real = None
    for el in elements:
        src = el.get("source_mapping", {})
        fn  = src.get("filename_absolute", src.get("filename_used", ""))
        if fn and fn.endswith(".sol") and os.path.exists(fn):
            arquivo_real = fn
            break

    alvo_real = arquivo_real or alvo
    if not lines_range or not os.path.exists(alvo_real):
        return _read_full_sol(alvo_real)

    try:
        with open(alvo_real, encoding="utf-8") as f:
            all_lines = f.readlines()
        start  = max(0, min(lines_range) - 3)
        end    = min(len(all_lines), max(lines_range) + 5)
        trecho = "".join(all_lines[start:end])
        return f"// {alvo_real} linhas {start+1}-{end}:\n{trecho}"
    except OSError:
        return _read_full_sol(alvo_real)


def _read_full_sol(alvo: str) -> str:
    try:
        if alvo and alvo.endswith(".sol") and os.path.exists(alvo):
            with open(alvo, encoding="utf-8") as f:
                src = f.read()
            return src[:6000] + "\n... (truncado)" if len(src) > 6000 else src
    except OSError:
        pass
    return "(codigo-fonte nao disponivel)"


def _extract_source_web2(finding: dict) -> str:
    """
    Extrai o trecho de código para findings Web2.

    Ordem de prioridade:
    1. raw_source já populado pelo adapter (Semgrep extra.lines)
    2. Leitura direta do arquivo via source_mapping (filename_absolute + lines)
    3. Leitura do arquivo usando filename_short resolvido a partir do cwd
    4. Fallback explícito informando que o código não pôde ser lido

    O problema "requires login" ocorre quando o Semgrep não consegue
    retornar o trecho (ex: arquivo atrás de autenticação ou path absoluto
    incorreto). As etapas 2 e 3 cobrem esse caso lendo diretamente do disco.
    """
    # Etapa 1: raw_source do adapter
    raw = finding.get("raw_source", "").strip()
    if raw and raw != "requires login":
        return raw

    # Etapa 2 e 3: leitura direta do arquivo
    for el in finding.get("elements", []):
        src      = el.get("source_mapping", {})
        lines    = src.get("lines", [])
        if not lines:
            continue

        # Tenta filename_absolute primeiro, depois filename_short relativo ao cwd
        candidates = []
        abs_path = src.get("filename_absolute", "")
        short_path = src.get("filename_short", "")
        if abs_path:
            candidates.append(abs_path)
        if short_path:
            candidates.append(short_path)
            candidates.append(os.path.join(os.getcwd(), short_path))

        for filepath in candidates:
            if not filepath or not os.path.exists(filepath):
                continue
            try:
                with open(filepath, encoding="utf-8", errors="replace") as fh:
                    all_lines = fh.readlines()
                start  = max(0, min(lines) - 3)
                end    = min(len(all_lines), max(lines) + 5)
                trecho = "".join(all_lines[start:end])
                if trecho.strip():
                    return f"// {filepath} linhas {start+1}-{end}:\n{trecho}"
            except OSError:
                continue

    return "(codigo-fonte nao disponivel — arquivo nao acessivel localmente)"


# ═══════════════════════════════════════════════════════════════════════════════
#  API pública
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_finding(finding: dict, alvo: str, client, target: str = "web3",
                    model: str = None, provider: str = "groq") -> dict:
    """
    Analisa um finding individual com a IA.

    Args:
        finding:  dicionário normalizado do finding.
        alvo:     caminho do alvo (arquivo ou diretório).
        client:   instância do cliente (Groq ou Anthropic).
        target:   "web3" (padrão) ou "web2".
        model:    chave do modelo no dicionário do provider.
        provider: "groq" (padrão) ou "anthropic".
    """
    system_prompt, _ = _get_system_prompts(target)
    element_name     = _extract_element_name(finding)

    if target == "web2":
        trecho_fonte  = _extract_source_web2(finding)
        user_template = _USER_FINDING_WEB2
    else:
        trecho_fonte  = _extract_source_web3(alvo, finding)
        user_template = _USER_FINDING_WEB3

    # Se o finding agrupa múltiplas ocorrências do mesmo check no mesmo arquivo,
    # informa a IA para que analise o contexto completo, não apenas uma linha.
    n_elements = len(finding.get("elements", []))
    descricao  = finding.get("description", "").strip()
    if n_elements > 1:
        linhas = []
        for el in finding.get("elements", []):
            lns = el.get("source_mapping", {}).get("lines", [])
            if lns:
                linhas.append(str(lns[0]))
        descricao = (
            f"[{n_elements} ocorrências agrupadas — linhas {', '.join(linhas)}]\n"
            + descricao
        )

    user_prompt = user_template.format(
        alvo         = alvo,
        detector     = finding.get("check", "N/A"),
        funcao       = element_name,
        impacto      = finding.get("impact", "N/A"),
        confianca    = finding.get("confidence", "N/A"),
        descricao    = descricao,
        trecho_fonte = trecho_fonte,
    )

    return _call_ai(client, provider, system_prompt, user_prompt, model=model)


def analyze_executive_summary(findings_ai: list, client, target: str = "web3",
                               model: str = None, provider: str = "groq") -> dict:
    """
    Gera resumo executivo consolidado a partir dos findings já analisados pela IA.

    Args:
        findings_ai: lista de findings enriquecidos.
        client:      instância do cliente (Groq ou Anthropic).
        target:      "web3" (padrão) ou "web2".
        model:       chave do modelo no dicionário do provider.
        provider:    "groq" (padrão) ou "anthropic".
    """
    _, system_prompt = _get_system_prompts(target)

    compact = [
        {
            "n":          i,
            "titulo":     f.get("titulo", f.get("check", "N/A")),
            "severidade": f.get("severidade", f.get("impact", "N/A")),
            "cvss":       f.get("cvss_score", "N/A"),
            "impacto":    f.get("impacto_financeiro", ""),
        }
        for i, f in enumerate(findings_ai, 1)
    ]

    user_prompt = _USER_EXECUTIVE.format(
        total         = len(findings_ai),
        findings_json = json.dumps(compact, ensure_ascii=False, indent=2),
    )

    return _call_ai(client, provider, system_prompt, user_prompt, model=model)