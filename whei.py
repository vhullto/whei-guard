#!/usr/bin/env python3
"""
Whei Guard — CLI de análise de segurança empresarial.
Suporte a Web3 (Slither) e Web2 (Semgrep) via padrão Adapter.

Uso:
  whei scan <alvo> [--target web3|web2] [--ai] [--json F] [--html F] [--only SEV]
  whei list
"""

import argparse
import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
ORANGE = "\033[38;5;214m"

SEVERITY_COLOR = {
    "High": RED, "Medium": YELLOW, "Low": BLUE,
    "Informational": GRAY, "Optimization": GREEN,
}
SEVERITY_EMOJI = {
    "High": "🔴", "Medium": "🟡", "Low": "🔵",
    "Informational": "⚪", "Optimization": "🟢",
}
SEVERITY_ORDER = {
    "High": 0, "Medium": 1, "Low": 2,
    "Informational": 3, "Optimization": 4,
}
CVSS_COLOR = {
    "Critical": RED, "High": RED, "Medium": YELLOW,
    "Low": BLUE, "Informational": GRAY,
}

# Semgrep severity → modelo interno
_SEMGREP_SEVERITY_MAP = {
    "ERROR":   "High",
    "WARNING": "Medium",
    "INFO":    "Low",
    "NOTE":    "Informational",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Adapter — Semgrep → estrutura interna normalizada
# ═══════════════════════════════════════════════════════════════════════════════

def _read_source_lines(filename: str, lines: list) -> str:
    """Lê trecho de código com ±3 linhas de contexto."""
    if not filename or not os.path.exists(filename):
        return ""
    try:
        with open(filename, encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()
        start = max(0, min(lines) - 3)
        end   = min(len(all_lines), max(lines) + 4)
        return "".join(all_lines[start:end])
    except OSError:
        return ""


def run_semgrep_adapter(alvo: str, semgrep_config: str = "auto") -> list:
    """
    Executa `semgrep scan --config <semgrep_config> --json <alvo>` e normaliza
    a saída para a estrutura interna do Whei Guard.

    Args:
        alvo:           Caminho do alvo (arquivo ou diretório).
        semgrep_config: Config Semgrep — "auto", "p/owasp-top-ten",
                        "p/secrets", "p/javascript", ou caminho local.

    Estrutura por finding:
    {
        "impact":      "High" | "Medium" | "Low" | "Informational",
        "confidence":  "High",
        "check":       "regra.id",
        "description": "mensagem da regra",
        "elements": [{
            "type": "source_code",
            "name": "regra.id",
            "source_mapping": {
                "filename_absolute": "/abs/path/file.py",
                "filename_short":    "file.py",
                "lines":             [10, 11],
            }
        }],
        "raw_source": "trecho do código",
        "wiki_url":   "https://semgrep.dev/r/<rule_id>",
    }

    Raises:
        FileNotFoundError  — semgrep não encontrado no PATH.
        RuntimeError       — erro real do subprocesso ou parse JSON.
    """
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", semgrep_config, "--json", alvo],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "Semgrep não encontrado no PATH.\n"
            "Instale com:  pip install semgrep\n"
            "          ou: brew install semgrep"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Timeout ao executar Semgrep (>300 s).")

    # Exit 1 = findings encontrados (comportamento normal do Semgrep).
    # Exit 2+ = erro real de execução.
    if proc.returncode >= 2:
        stderr = proc.stderr.strip()[:600] if proc.stderr else "(sem stderr)"
        raise RuntimeError(
            f"Semgrep terminou com erro (exit {proc.returncode}).\n{stderr}"
        )

    stdout = proc.stdout.strip()
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Falha ao parsear JSON do Semgrep: {exc}")

    # ── Agrupa por (check_id, filename) para deduplicar findings repetidos ──────
    # Mesmo check na mesma linha de arquivos distintos = finding distinto.
    # Mesmo check em linhas próximas do MESMO arquivo = agrupado em um finding.
    grouped: dict[tuple, dict] = {}

    for item in data.get("results", []):
        check_id = item.get("check_id", "unknown")
        message  = item.get("extra", {}).get("message", "")
        severity = item.get("extra", {}).get("severity", "INFO")
        impact   = _SEMGREP_SEVERITY_MAP.get(severity.upper(), "Informational")
        filename = item.get("path", "")
        start_ln = item.get("start", {}).get("line", 1)
        end_ln   = item.get("end",   {}).get("line", start_ln)
        lines    = list(range(start_ln, end_ln + 1))

        raw_source = item.get("extra", {}).get("lines", "").strip()
        if not raw_source:
            raw_source = _read_source_lines(filename, lines)

        key = (check_id, filename)

        if key not in grouped:
            grouped[key] = {
                "impact":      impact,
                "confidence":  "High",
                "check":       check_id,
                "description": message,
                "elements": [],
                "raw_source":  raw_source,
                "wiki_url":    f"https://semgrep.dev/r/{check_id}",
                "_all_lines":  [],
            }

        grouped[key]["elements"].append({
            "type": "source_code",
            "name": check_id,
            "source_mapping": {
                "filename_absolute": os.path.abspath(filename) if filename else "",
                "filename_short":    os.path.basename(filename) if filename else "",
                "lines":             lines,
            },
        })
        grouped[key]["_all_lines"].extend(lines)

        # Atualiza raw_source para cobrir o intervalo completo de linhas
        if grouped[key]["_all_lines"] and filename:
            grouped[key]["raw_source"] = _read_source_lines(
                filename, grouped[key]["_all_lines"]
            ) or raw_source

    # Remove campo auxiliar antes de retornar
    findings = []
    for f in grouped.values():
        f.pop("_all_lines", None)
        findings.append(f)

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers de terminal
# ═══════════════════════════════════════════════════════════════════════════════

def _supports_color():
    return sys.stdout.isatty() and os.name != "nt"


def c(text, color, use_color=True):
    return f"{color}{text}{RESET}" if use_color else text


def print_banner(use_color=True):
    o = ORANGE if use_color else ""
    d = DIM    if use_color else ""
    r = RESET  if use_color else ""
    print(f"""
{o}{BOLD}
 ██╗    ██╗██╗  ██╗███████╗██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ██║    ██║██║  ██║██╔════╝██║    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██║ █╗ ██║███████║█████╗  ██║    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║███╗██║██╔══██║██╔══╝  ██║    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚███╔███╔╝██║  ██║███████╗██║    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝{r}
{d}  Enterprise AppSec Analyzer  //  powered by Slither + Semgrep + Groq AI{r}
""")


def print_finding_static(r, index, exploit_info, use_color=True):
    impact     = r.get("impact", "Low")
    confidence = r.get("confidence", "N/A")
    check      = r.get("check", "N/A")
    desc       = r.get("description", "").strip()
    elements   = r.get("elements", [])
    raw_source = r.get("raw_source", "")
    col        = SEVERITY_COLOR.get(impact, GRAY) if use_color else ""
    emoji      = SEVERITY_EMOJI.get(impact, "⚪")

    print(f"\n{c('─' * 70, GRAY, use_color)}")
    print(f"{c(f'[{index}]', BOLD, use_color)} {emoji}  {c(impact.upper(), col+BOLD, use_color)}"
          f"  {c(check, BOLD, use_color)}  {c(f'(confiança: {confidence})', DIM, use_color)}")

    if exploit_info:
        if exploit_info.get("exploitavel"):
            print(f"  {c('⚡ EXPLOITAVEL', ORANGE+BOLD, use_color)}  "
                  f"{c(exploit_info.get('razao', ''), DIM, use_color)}")
        else:
            print(f"  {c('✓ Baixo risco', GRAY, use_color)}  "
                  f"{c(exploit_info.get('razao', ''), DIM, use_color)}")

    print()
    for line in desc.splitlines():
        line = line.strip()
        if not line:
            continue
        print(f"    {c(line, DIM, use_color)}" if line.startswith("-")
              else f"  {c(line, CYAN, use_color)}")

    if elements:
        print(f"\n  {c('Elementos afetados:', DIM, use_color)}")
        for el in elements:
            el_type  = el.get("type", "")
            el_name  = el.get("name", "")
            src      = el.get("source_mapping", {})
            filename = src.get("filename_short", src.get("filename_used", ""))
            lines    = src.get("lines", [])
            loc      = f"{filename}:{lines[0]}" if lines else filename
            print(f"    {c(f'[{el_type}]', GRAY, use_color)} {el_name}"
                  f"  {c(f'->  {loc}', DIM, use_color)}")

    # Trecho de código: presente em Web2 (Semgrep), ausente em Web3.
    if raw_source:
        print(f"\n  {c('Trecho:', DIM, use_color)}")
        for line in raw_source.splitlines()[:12]:
            print(f"    {c(line, GREEN, use_color)}")


def _ai_block(title, content, use_color):
    if not content:
        return
    print(f"\n  {c(f'-- {title} ', GRAY, use_color)}")
    for line in content.splitlines():
        print(f"  {line}")


def print_finding_ai(ai, index, use_color=True):
    if "erro" in ai:
        print(f"\n  {c('[AI] Erro:', YELLOW, use_color)} {ai['erro']}")
        return

    print(f"\n  {c('.' * 70, GRAY, use_color)}")
    print(f"  {c('✦ ANALISE IA', ORANGE+BOLD, use_color)}\n")

    cvss  = ai.get("cvss_score", "N/A")
    vetor = ai.get("cvss_vetor", "")
    sev   = ai.get("severidade", "")
    col   = CVSS_COLOR.get(sev, GRAY) if use_color else ""
    print(f"  {c('CVSS:', BOLD, use_color)} {c(str(cvss), col+BOLD, use_color)}"
          f"  {c(sev, col, use_color)}  {c(vetor, DIM, use_color)}")

    _ai_block("RISCO TECNICO",      ai.get("explicacao_tecnica", ""), use_color)
    _ai_block("CENARIO DE EXPLOIT", ai.get("cenario_exploit", ""),    use_color)

    poc = ai.get("poc_code", "")
    if poc:
        print(f"\n  {c('-- POC --------------------------------------------------', GRAY, use_color)}")
        for line in poc.splitlines():
            print(f"  {c(line, GREEN, use_color)}")

    _ai_block("COMO REPRODUZIR",    ai.get("como_reproduzir", ""),    use_color)
    _ai_block("IMPACTO",            ai.get("impacto_financeiro", ""), use_color)

    fix = ai.get("codigo_corrigido", "")
    if fix:
        print(f"\n  {c('-- FIX SUGERIDO -----------------------------------------', GRAY, use_color)}")
        for line in fix.splitlines():
            print(f"  {c(line, CYAN, use_color)}")

    template = ai.get("template_submissao", "")
    if template:
        print(f"\n  {c('-- TEMPLATE DE SUBMISSAO --------------------------------', GRAY, use_color)}")
        for line in template.splitlines():
            print(f"  {line}")


def print_executive_summary(exec_ai, use_color=True):
    if "erro" in exec_ai:
        print(f"\n{c('[AI] Erro resumo executivo:', YELLOW, use_color)} {exec_ai['erro']}")
        return

    sep = "=" * 70
    print(f"\n{c(sep, ORANGE, use_color)}")
    print(f"{c('  ✦ RESUMO EXECUTIVO', ORANGE+BOLD, use_color)}")
    print(f"{c(sep, ORANGE, use_color)}\n")

    risco = exec_ai.get("risco_geral", "N/A")
    score = exec_ai.get("score_seguranca", "N/A")
    col   = CVSS_COLOR.get(risco, GRAY) if use_color else ""
    print(f"  {c('Risco geral:', BOLD, use_color)}     {c(risco, col+BOLD, use_color)}")
    print(f"  {c('Score seguranca:', BOLD, use_color)}  {score}/100")

    crit = exec_ai.get("total_critical", 0)
    high = exec_ai.get("total_high", 0)
    med  = exec_ai.get("total_medium", 0)
    low  = exec_ai.get("total_low", 0)
    print(f"\n  {c('Critical:', RED, use_color)} {crit}  "
          f"{c('High:', RED, use_color)} {high}  "
          f"{c('Medium:', YELLOW, use_color)} {med}  "
          f"{c('Low:', BLUE, use_color)} {low}")

    vetor = exec_ai.get("vetor_principal", "")
    if vetor:
        print(f"\n  {c('Vetor principal:', BOLD, use_color)}\n  {vetor}")

    resumo = exec_ai.get("resumo_geral", "")
    if resumo:
        print(f"\n  {c('Analise:', BOLD, use_color)}")
        for line in resumo.splitlines():
            print(f"  {line}")

    priorizados = exec_ai.get("findings_priorizados", [])
    if priorizados:
        print(f"\n  {c('Ordem de remediacao recomendada:', BOLD, use_color)}")
        for f in sorted(priorizados, key=lambda x: x.get("prioridade", 99)):
            n   = f.get("prioridade", "?")
            tit = f.get("titulo", "")
            why = f.get("razao", "")
            print(f"    {c(f'#{n}', ORANGE, use_color)} {tit}")
            if why:
                print(f"       {c(why, DIM, use_color)}")

    recs = exec_ai.get("recomendacoes_imediatas", [])
    if recs:
        print(f"\n  {c('Acoes imediatas:', BOLD, use_color)}")
        for r in recs:
            print(f"    {c('->', ORANGE, use_color)} {r}")

    estrategia = exec_ai.get("estrategia_submissao", "")
    if estrategia:
        print(f"\n  {c('Estrategia:', BOLD, use_color)}")
        for line in estrategia.splitlines():
            print(f"  {line}")

    print(f"\n{c(sep, ORANGE, use_color)}\n")


def print_summary_static(findings_exploitaveis, findings_skipped, include_low, use_color=True):
    n_exploitaveis = len(findings_exploitaveis)
    n_baixo_risco  = len(findings_skipped)

    print(f"\n{'─'*70}")
    print(f"\n{c('Resumo:', BOLD, use_color)}")

    if n_exploitaveis == 0:
        print(f"  {c('✓ Nenhuma vulnerabilidade encontrada.', ORANGE, use_color)}")
    else:
        counts = {}
        for r in findings_exploitaveis:
            impact = r.get("impact", "Low")
            counts[impact] = counts.get(impact, 0) + 1
        for sev in ["High", "Medium", "Low", "Informational", "Optimization"]:
            n = counts.get(sev, 0)
            if n:
                col   = SEVERITY_COLOR.get(sev, GRAY) if use_color else ""
                emoji = SEVERITY_EMOJI.get(sev, "")
                print(f"  {emoji}  {c(f'{sev:<16}', col, use_color)} {c(str(n), BOLD, use_color)}")
        print(f"\n  {c('Total:', BOLD, use_color)} {c(str(n_exploitaveis), ORANGE, use_color)}", end="")

    if n_baixo_risco > 0:
        suffix = (
            f"  {c(f'({n_baixo_risco} de baixo risco visíveis)', DIM, use_color)}"
            if include_low else
            f"  {c(f'({n_baixo_risco} filtrados — use --include-low para ver)', DIM, use_color)}"
        )
        print(suffix)
    else:
        print()


# ═══════════════════════════════════════════════════════════════════════════════
#  Helper Web3
# ═══════════════════════════════════════════════════════════════════════════════

def _get_funcao_e_contrato(r, sl):
    elements = r.get("elements", [])
    for el in elements:
        if el.get("type") != "function":
            continue
        nome_func = el.get("name", "")
        src       = el.get("source_mapping", {})
        filename  = src.get("filename_absolute", src.get("filename_used", ""))
        for contrato in sl.contracts:
            arq = contrato.source_mapping.filename.absolute
            if filename and filename != arq:
                continue
            for funcao in contrato.functions:
                if funcao.name == nome_func:
                    return funcao, contrato
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
#  Comandos
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_scan(args):
    alvo        = args.alvo
    target      = args.target            # "web3" | "web2"
    model         = args.model           # depende do provider
    provider      = args.provider         # "groq" | "anthropic"
    semgrep_config = args.semgrep_config  # "auto" | "p/owasp-top-ten" | etc
    only        = args.only.capitalize() if args.only else None
    export_json = args.json
    export_html = args.html
    use_ai      = args.ai
    include_low = args.include_low
    use_color   = _supports_color() and not args.no_color

    print_banner(use_color)
    print(f"  {'Alvo':<20} {alvo}")
    print(f"  {'Modo':<20} {c(target.upper(), ORANGE, use_color)}")
    print(f"  {'Filtro':<20} {only or 'todos'}")
    print(f"  {'IA (Groq)':<20} {c('✦ ativa', ORANGE, use_color) if use_ai else '—'}")
    if use_ai:
        from whei_ai import GROQ_MODELS, ANTHROPIC_MODELS
        _models = ANTHROPIC_MODELS if provider == "anthropic" else GROQ_MODELS
        _model_display = model or ("sonnet" if provider == "anthropic" else "scout")
        print(f"  {'Provider':<20} {c(provider.upper(), ORANGE, use_color)}")
        print(f"  {'Modelo':<20} {c(_model_display, ORANGE, use_color)} {c(f'({_models.get(_model_display, _model_display)})', DIM, use_color)}")
    print(f"  {'Baixo risco':<20} {'visível' if include_low else 'filtrado'}")
    print(f"  {'JSON':<20} {export_json or '—'}")
    print(f"  {'HTML':<20} {export_html or '—'}")
    print()

    # ─── Branch Web2: Semgrep ─────────────────────────────────────────────────
    if target == "web2":
        print(f"  {c(f'[~] Executando Semgrep (config: {semgrep_config})...', DIM, use_color)}")
        try:
            findings = run_semgrep_adapter(alvo, semgrep_config=semgrep_config)
        except FileNotFoundError as exc:
            print(f"\n  {c('[x]', RED, use_color)} {exc}")
            sys.exit(2)
        except RuntimeError as exc:
            print(f"\n  {c('[x] Semgrep:', RED, use_color)} {exc}")
            sys.exit(2)

        print(f"  {c(f'[✓] {len(findings)} finding(s) encontrado(s).', DIM, use_color)}\n")

        if only:
            findings = [r for r in findings if r.get("impact") == only]

        findings.sort(key=lambda r: SEVERITY_ORDER.get(r.get("impact", "Low"), 99))

        # Web2: aplica validador de exploitabilidade para filtrar falsos positivos
        print(f"  {c('[~] Validando exploitabilidade (heurísticas Web2)...', DIM, use_color)}\n")
        from whei_ai import validar_exploitabilidade_web2
        findings_exploitaveis = []
        findings_skipped      = []
        exploit_map           = {}
        for r in findings:
            info = validar_exploitabilidade_web2(r)
            exploit_map[id(r)] = info
            (findings_skipped if info.get("skip") else findings_exploitaveis).append(r)
        detector_count = len(findings)

    # ─── Branch Web3: Slither ─────────────────────────────────────────────────
    else:
        try:
            from slither.slither import Slither
            from whei_rules import ALL_DETECTORS
            from whei_rules.exploitability import validar_exploitabilidade
        except ImportError as exc:
            print(f"  {c(f'[x] Import error: {exc}', RED, use_color)}")
            sys.exit(1)

        print(f"  {c('[~] Compilando contrato...', DIM, use_color)}")
        try:
            sl = Slither(alvo)
        except Exception as exc:
            print(f"  {c('[x] Falha ao compilar:', RED, use_color)} {exc}")
            sys.exit(1)

        print(f"  {c(f'[~] Executando {len(ALL_DETECTORS)} detector(es)...', DIM, use_color)}")
        for cls in ALL_DETECTORS:
            sl.register_detector(cls)

        raw_results = sl.run_detectors()
        todos       = [r for grupo in raw_results for r in grupo]
        nossos_args = {cls.ARGUMENT for cls in ALL_DETECTORS}
        findings    = [r for r in todos if r.get("check") in nossos_args]

        if only:
            findings = [r for r in findings if r.get("impact") == only]

        findings.sort(key=lambda r: SEVERITY_ORDER.get(r.get("impact", "Low"), 99))

        print(f"  {c('[~] Validando exploitabilidade...', DIM, use_color)}\n")

        findings_exploitaveis = []
        findings_skipped      = []
        exploit_map           = {}

        for r in findings:
            funcao, contrato = _get_funcao_e_contrato(r, sl)
            info = (
                validar_exploitabilidade(r, funcao, contrato)
                if funcao and contrato else
                {"exploitavel": True, "confianca": "media",
                 "razao": "Nao foi possivel recuperar objeto da funcao", "skip": False}
            )
            exploit_map[id(r)] = info
            (findings_skipped if info.get("skip") else findings_exploitaveis).append(r)

        detector_count = len(ALL_DETECTORS)

    # ─── Findings a exibir ────────────────────────────────────────────────────
    findings_exibir = list(findings_exploitaveis)
    if include_low:
        findings_exibir += findings_skipped
        findings_exibir.sort(key=lambda r: SEVERITY_ORDER.get(r.get("impact", "Low"), 99))

    # ─── Inicializa Groq ──────────────────────────────────────────────────────
    groq_client  = None
    findings_ai  = []
    executive_ai = {}

    if use_ai and findings_exploitaveis:
        print(f"  {c('[~] Inicializando Groq AI...', DIM, use_color)}")
        try:
            from whei_ai import _get_client, GROQ_MODELS, ANTHROPIC_MODELS
            groq_client, _ = _get_client(provider=provider)
            _models = ANTHROPIC_MODELS if provider == "anthropic" else GROQ_MODELS
            _model_display = model or ("sonnet" if provider == "anthropic" else "scout")
            model_id = _models.get(_model_display, _model_display)
            print(f"  {c(f'[✓] {provider.capitalize()} conectado — {model_id}', ORANGE, use_color)}\n")
        except Exception as exc:
            print(f"  {c(f'[!] Groq indisponivel: {exc}', YELLOW, use_color)}\n")
            use_ai = False

    # ─── Output por finding ───────────────────────────────────────────────────
    if not findings_exibir:
        print(f"\n  {c('✓ Nenhuma vulnerabilidade encontrada.', ORANGE, use_color)}")
        if findings_skipped:
            print(f"  {c(f'  ({len(findings_skipped)} filtrados — use --include-low)', DIM, use_color)}")
    else:
        for i, r in enumerate(findings_exibir, 1):
            exploit_info  = exploit_map.get(id(r))
            e_exploitavel = not (exploit_info or {}).get("skip", False)
            print_finding_static(r, i, exploit_info, use_color)

            if use_ai and groq_client and e_exploitavel:
                print(f"\n  {c('[~] Consultando IA...', DIM, use_color)}", end="", flush=True)
                try:
                    from whei_ai import analyze_finding
                    ai_result = analyze_finding(r, alvo, groq_client, target=target, model=model, provider=provider)
                    findings_ai.append({**r, **ai_result, "_exploit_info": exploit_info})
                    print(f"\r  {c('[✓] IA concluida              ', ORANGE, use_color)}")
                    print_finding_ai(ai_result, i, use_color)
                except Exception as exc:
                    findings_ai.append({**r, "erro": str(exc)})
                    print(f"\r  {c(f'[!] Erro IA: {exc}', YELLOW, use_color)}")
            else:
                findings_ai.append({**r, "_exploit_info": exploit_info})

    # ─── Resumo estático ──────────────────────────────────────────────────────
    print_summary_static(findings_exploitaveis, findings_skipped, include_low, use_color)

    # ─── Resumo executivo IA ──────────────────────────────────────────────────
    if use_ai and groq_client and findings_exploitaveis:
        ai_exploitaveis = [
            f for f in findings_ai
            if not (f.get("_exploit_info") or {}).get("skip")
        ]
        if ai_exploitaveis:
            print(f"\n  {c('[~] Gerando resumo executivo...', DIM, use_color)}", end="", flush=True)
            try:
                from whei_ai import analyze_executive_summary
                executive_ai = analyze_executive_summary(
                    ai_exploitaveis, groq_client, target=target, model=model, provider=provider
                )
                print(f"\r  {c('[✓] Resumo concluido           ', ORANGE, use_color)}")
                print_executive_summary(executive_ai, use_color)
            except Exception as exc:
                print(f"\r  {c(f'[!] Erro resumo: {exc}', YELLOW, use_color)}")

    # ─── Exportar JSON ────────────────────────────────────────────────────────
    if export_json:
        payload = {
            "meta": {
                "target":                alvo,
                "domain":                target,
                "date":                  datetime.now().isoformat(),
                "engine":                "semgrep" if target == "web2" else "slither",
                "ai":                    bool(use_ai),
                "total":                 len(findings),
                "exploitaveis":          len(findings_exploitaveis),
                "filtrados_baixo_risco": len(findings_skipped),
            },
            "findings":          findings_ai,
            "findings_skipped":  findings_skipped,
            "executive_summary": executive_ai,
        }
        try:
            with open(export_json, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
            print(f"\n  {c('[✓] JSON:', ORANGE, use_color)} {export_json}")
        except OSError as exc:
            print(f"\n  {c(f'[!] Erro ao salvar JSON: {exc}', YELLOW, use_color)}")

    # ─── Exportar HTML ────────────────────────────────────────────────────────
    if export_html:
        try:
            from whei_report import generate_html
            html = generate_html(
                target         = alvo,
                findings       = findings_ai,
                detector_count = detector_count,
                domain         = target,
            )
            with open(export_html, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"  {c('[✓] HTML:', ORANGE, use_color)} {export_html}")
        except OSError as exc:
            print(f"  {c(f'[!] Erro ao salvar HTML: {exc}', YELLOW, use_color)}")

    print()
    sys.exit(1 if findings_exploitaveis else 0)


def cmd_list(args):
    use_color = _supports_color()
    try:
        from whei_rules import ALL_DETECTORS
    except ImportError as exc:
        print(f"[x] {exc}")
        sys.exit(1)

    print_banner(use_color)
    print(f"  {'ARGUMENTO':<30} {'IMPACTO':<12} {'CONFIANCA':<12} DESCRICAO")
    print(f"  {'─'*28}  {'─'*10}  {'─'*10}  {'─'*30}")
    for cls in ALL_DETECTORS:
        impact     = cls.IMPACT.name.capitalize()
        confidence = cls.CONFIDENCE.name.capitalize()
        col        = SEVERITY_COLOR.get(impact, GRAY) if use_color else ""
        print(f"  {cls.ARGUMENT:<30} {c(f'{impact:<12}', col, use_color)} {confidence:<12} {cls.HELP}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="whei",
        description="Whei Guard — Enterprise AppSec Analyzer (Web2 + Web3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
exemplos:
  whei scan contrato.sol                         # Web3 com Slither (padrão)
  whei scan contrato.sol --ai                    # + análise Groq AI
  whei scan ./meu-repo --target web2             # Web2 com Semgrep
  whei scan ./meu-repo --target web2 --ai        # + análise Groq AI (scout padrão)
  whei scan ./meu-repo --target web2 --ai --model versatile  # usa llama-3.3-70b
  whei scan ./meu-repo --target web2 --ai --model qwen       # usa qwen3-32b
  whei scan ./meu-repo --target web2 --ai --html relatorio.html
  whei scan ./meu-repo --target web2 --semgrep-config p/owasp-top-ten --ai
  whei scan ./meu-repo --target web2 --semgrep-config p/secrets --only high
  whei scan ./meu-repo --target web2 --ai --provider anthropic --model sonnet
  whei scan contrato.sol --ai --provider anthropic --model haiku
  whei scan . --only high --json out.json
  whei list
        """,
    )
    subparsers = parser.add_subparsers(dest="comando")
    subparsers.required = True

    p_scan = subparsers.add_parser("scan", help="Analisa um alvo (contrato ou repositório)")
    p_scan.add_argument("alvo",
                        metavar="alvo",
                        help="Arquivo .sol, diretório ou endereço 0x...")
    p_scan.add_argument("--target",
                        choices=["web3", "web2"],
                        default="web3",
                        help="Motor: web3=Slither (padrão) | web2=Semgrep")
    p_scan.add_argument("--ai",          action="store_true", help="Ativar análise Groq AI")
    p_scan.add_argument("--model",
                        metavar="MODEL",
                        default=None,
                        help="Modelo: groq=[scout|versatile|qwen] | anthropic=[sonnet|haiku]")
    p_scan.add_argument("--provider",
                        choices=["groq", "anthropic"],
                        default="groq",
                        help="Provider de IA: groq (padrão, gratuito) | anthropic (pago, mais capaz)")
    p_scan.add_argument("--semgrep-config",
                        metavar="CFG",
                        default="auto",
                        help="Config Semgrep: auto (padrão), p/owasp-top-ten, p/secrets, p/javascript, ou caminho para regra local")
    p_scan.add_argument("--only",        metavar="SEV",       help="Filtrar: high | medium | low")
    p_scan.add_argument("--json",        metavar="arquivo",   help="Exportar JSON")
    p_scan.add_argument("--html",        metavar="arquivo",   help="Exportar relatório HTML")
    p_scan.add_argument("--no-color",    action="store_true", help="Desativar cores ANSI")
    p_scan.add_argument("--include-low", action="store_true", help="Incluir findings de baixo risco")
    p_scan.set_defaults(func=cmd_scan)

    p_list = subparsers.add_parser("list", help="Lista detectores Web3 disponíveis")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()