"""
whei_report.py — Gerador de relatório HTML para o Whei Guard.

Domain-aware: adapta subtitle, referências e engine conforme web2/web3.
Design: terminal hacker — dark, monoespaçado, verde/âmbar em fundo preto.
"""

from datetime import datetime
from typing import List, Dict, Any


SEVERITY_COLOR = {
    "High":          ("#ff4d4d", "🔴"),
    "Medium":        ("#ffaa00", "🟡"),
    "Low":           ("#4daaff", "🔵"),
    "Informational": ("#aaaaaa", "⚪"),
    "Optimization":  ("#88ff88", "🟢"),
}

# ── Configuração por domínio ──────────────────────────────────────────────────
# Adicionar domínio novo = adicionar entrada aqui. Nada mais muda.

_DOMAIN_CFG = {
    "web3": {
        "subtitle":   "Smart Contract Security Analyzer",
        "engine":     "Slither",
        "references": (
            'Referências: '
            '<a href="https://swcregistry.io" style="color:var(--dim)">SWC Registry</a>'
            ' &nbsp;|&nbsp; '
            '<a href="https://github.com/crytic/slither" style="color:var(--dim)">Slither</a>'
        ),
    },
    "web2": {
        "subtitle":   "Enterprise AppSec Analyzer",
        "engine":     "Semgrep",
        "references": (
            'Referências: '
            '<a href="https://owasp.org/www-project-top-ten/" style="color:var(--dim)">OWASP Top 10</a>'
            ' &nbsp;|&nbsp; '
            '<a href="https://semgrep.dev/docs/" style="color:var(--dim)">Semgrep Docs</a>'
            ' &nbsp;|&nbsp; '
            '<a href="https://cwe.mitre.org/" style="color:var(--dim)">CWE/MITRE</a>'
        ),
    },
}

# ── HTML Template ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Whei Guard — {subtitle}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet"/>
<style>
  :root {{
    --bg:        #0a0a0f;
    --bg2:       #0f0f1a;
    --bg3:       #13131f;
    --border:    #1e1e3a;
    --green:     #00ff88;
    --amber:     #ffaa00;
    --red:       #ff4d4d;
    --blue:      #4daaff;
    --dim:       #555577;
    --text:      #c8c8e8;
    --mono:      'Share Tech Mono', monospace;
    --display:   'Orbitron', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 13px;
    line-height: 1.6;
    min-height: 100vh;
  }}
  body::before {{
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,0,0,0.08) 2px, rgba(0,0,0,0.08) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }}
  header {{
    border-bottom: 1px solid var(--border);
    padding: 2rem 2.5rem 1.5rem;
    background: var(--bg2);
    position: relative;
    overflow: hidden;
  }}
  header::after {{
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--green), transparent);
  }}
  .logo {{
    font-family: var(--display);
    font-size: 1.8rem;
    font-weight: 900;
    color: var(--green);
    letter-spacing: 0.15em;
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
  }}
  .logo span {{ color: var(--amber); }}
  .subtitle {{
    color: var(--dim);
    font-size: 11px;
    letter-spacing: 0.2em;
    margin-top: 0.25rem;
  }}
  .meta {{
    margin-top: 1rem;
    display: flex;
    gap: 2rem;
    flex-wrap: wrap;
  }}
  .meta-item {{ color: var(--dim); }}
  .meta-item strong {{ color: var(--text); }}
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    padding: 2rem 2.5rem;
  }}
  .summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }}
  .card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1.2rem 1.5rem;
    transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: var(--green); }}
  .card-label {{
    font-size: 10px;
    letter-spacing: 0.2em;
    color: var(--dim);
    text-transform: uppercase;
  }}
  .card-value {{
    font-family: var(--display);
    font-size: 2rem;
    font-weight: 700;
    margin-top: 0.3rem;
    line-height: 1;
  }}
  .card-value.high   {{ color: var(--red);   text-shadow: 0 0 15px rgba(255,77,77,0.4); }}
  .card-value.medium {{ color: var(--amber); text-shadow: 0 0 15px rgba(255,170,0,0.4); }}
  .card-value.low    {{ color: var(--blue);  text-shadow: 0 0 15px rgba(77,170,255,0.4); }}
  .card-value.total  {{ color: var(--green); text-shadow: 0 0 15px rgba(0,255,136,0.4); }}
  .section-title {{
    font-family: var(--display);
    font-size: 0.7rem;
    letter-spacing: 0.3em;
    color: var(--dim);
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    margin-bottom: 1.5rem;
  }}
  .finding {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--border);
    border-radius: 4px;
    margin-bottom: 1rem;
    overflow: hidden;
    transition: border-color 0.2s;
  }}
  .finding.high   {{ border-left-color: var(--red);   }}
  .finding.medium {{ border-left-color: var(--amber); }}
  .finding.low    {{ border-left-color: var(--blue);  }}
  .finding-header {{
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.8rem 1.2rem;
    cursor: pointer;
    user-select: none;
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
  }}
  .finding-header:hover {{ background: #16162a; }}
  .badge {{
    font-family: var(--display);
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.15em;
    padding: 3px 8px;
    border-radius: 2px;
    white-space: nowrap;
  }}
  .badge.high   {{ background: rgba(255,77,77,0.15);  color: var(--red);   border: 1px solid rgba(255,77,77,0.3);   }}
  .badge.medium {{ background: rgba(255,170,0,0.15);  color: var(--amber); border: 1px solid rgba(255,170,0,0.3);   }}
  .badge.low    {{ background: rgba(77,170,255,0.15); color: var(--blue);  border: 1px solid rgba(77,170,255,0.3);  }}
  .finding-title {{
    flex: 1;
    color: var(--text);
    font-size: 13px;
  }}
  .finding-toggle {{
    color: var(--dim);
    font-size: 10px;
    transition: transform 0.2s;
  }}
  .finding.open .finding-toggle {{ transform: rotate(180deg); }}
  .finding-body {{
    display: none;
    padding: 1.2rem;
  }}
  .finding.open .finding-body {{ display: block; }}
  .field {{ margin-bottom: 1rem; }}
  .field-label {{
    font-size: 10px;
    letter-spacing: 0.2em;
    color: var(--dim);
    text-transform: uppercase;
    margin-bottom: 0.3rem;
  }}
  .field-value {{ color: var(--text); }}
  pre.code-block {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 0.8rem 1rem;
    overflow-x: auto;
    font-size: 12px;
    color: var(--green);
    white-space: pre-wrap;
    word-break: break-word;
  }}
  .no-findings {{
    text-align: center;
    padding: 3rem;
    color: var(--green);
    font-family: var(--display);
    font-size: 1.1rem;
    letter-spacing: 0.2em;
    text-shadow: 0 0 20px rgba(0,255,136,0.3);
  }}
  footer {{
    border-top: 1px solid var(--border);
    padding: 1.5rem 2.5rem;
    text-align: center;
    color: var(--dim);
    font-size: 11px;
    letter-spacing: 0.1em;
  }}
  @media (max-width: 600px) {{
    header, .container {{ padding: 1rem; }}
    .logo {{ font-size: 1.3rem; }}
  }}
</style>
</head>
<body>

<header>
  <div class="logo">WHEI<span>GUARD</span></div>
  <div class="subtitle">// {subtitle}</div>
  <div class="meta">
    <div class="meta-item">TARGET <strong>{target}</strong></div>
    <div class="meta-item">MODE <strong>{domain}</strong></div>
    <div class="meta-item">ENGINE <strong>{engine}</strong></div>
    <div class="meta-item">DATE <strong>{date}</strong></div>
    <div class="meta-item">FINDINGS <strong>{detector_count}</strong></div>
    <div class="meta-item">STATUS <strong style="color:var(--{status_color})">{status}</strong></div>
  </div>
</header>

<div class="container">

  <div class="summary">
    <div class="card">
      <div class="card-label">Total</div>
      <div class="card-value total">{total}</div>
    </div>
    <div class="card">
      <div class="card-label">High</div>
      <div class="card-value high">{count_high}</div>
    </div>
    <div class="card">
      <div class="card-label">Medium</div>
      <div class="card-value medium">{count_medium}</div>
    </div>
    <div class="card">
      <div class="card-label">Low</div>
      <div class="card-value low">{count_low}</div>
    </div>
  </div>

  <div class="section-title">// Findings</div>

  {findings_html}

</div>

<footer>
  Gerado por WheiGuard v1.1.0 &nbsp;|&nbsp; {date} &nbsp;|&nbsp; {references}
</footer>

<script>
  document.querySelectorAll('.finding-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.closest('.finding').classList.toggle('open');
    }});
  }});
  document.querySelectorAll('.finding.high').forEach(f => f.classList.add('open'));
</script>

</body>
</html>
"""

FINDING_TEMPLATE = """\
<div class="finding {severity_class}">
  <div class="finding-header">
    <span class="badge {severity_class}">{severity_emoji} {impact}</span>
    <span class="finding-title">{check}</span>
    <span class="badge" style="border-color:var(--border);color:var(--dim)">
      confiança: {confidence}
    </span>
    <span class="finding-toggle">▼</span>
  </div>
  <div class="finding-body">
    <div class="field">
      <div class="field-label">Descrição</div>
      <pre class="code-block">{description}</pre>
    </div>
    <div class="field">
      <div class="field-label">Elementos afetados</div>
      <pre class="code-block">{elements}</pre>
    </div>
    {raw_source_block}
    <div class="field">
      <div class="field-label">Referência</div>
      <div class="field-value">
        <a href="{wiki}" style="color:var(--blue)" target="_blank">{wiki}</a>
      </div>
    </div>
  </div>
</div>
"""

_RAW_SOURCE_BLOCK = """\
    <div class="field">
      <div class="field-label">Trecho de código</div>
      <pre class="code-block">{raw_source}</pre>
    </div>"""


# ── Funções auxiliares ────────────────────────────────────────────────────────

def _severity_class(impact: str) -> str:
    return {"High": "high", "Medium": "medium", "Low": "low"}.get(impact, "low")


def _format_elements(elements: list) -> str:
    lines = []
    for el in elements:
        t         = el.get("type", "")
        name      = el.get("name", "")
        src       = el.get("source_mapping", {})
        filename  = src.get("filename_short", src.get("filename_absolute", ""))
        lines_src = src.get("lines", [])
        loc       = f"{filename}:{lines_src[0]}" if lines_src else filename
        lines.append(f"[{t}] {name}  →  {loc}")
    return "\n".join(lines) if lines else "N/A"


def _esc(text: str) -> str:
    """Escapa caracteres HTML mínimos para uso em blocos <pre>."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── API pública ───────────────────────────────────────────────────────────────

def generate_html(
    target: str,
    findings: List[Dict[str, Any]],
    detector_count: int,
    domain: str = "web3",
) -> str:
    """
    Gera o relatório HTML de segurança.

    Args:
        target:         Caminho ou identificador do alvo.
        findings:       Lista de findings normalizados.
        detector_count: Número de detectores/regras executadas.
        domain:         "web3" (padrão) ou "web2".
    """
    cfg        = _DOMAIN_CFG.get(domain, _DOMAIN_CFG["web3"])
    now        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    count_high = sum(1 for r in findings if r.get("impact") == "High")
    count_med  = sum(1 for r in findings if r.get("impact") == "Medium")
    count_low  = sum(1 for r in findings if r.get("impact") == "Low")
    total      = len(findings)

    if total == 0:
        findings_html = '<div class="no-findings">✓ NENHUMA VULNERABILIDADE DETECTADA</div>'
        status        = "CLEAN"
        status_color  = "green"
    else:
        status        = "VULNERÁVEL"
        status_color  = "red"
        blocks        = []
        for r in sorted(
            findings,
            key=lambda x: {"High": 0, "Medium": 1, "Low": 2}.get(x.get("impact", ""), 3),
        ):
            impact   = r.get("impact", "Low")
            _, emoji = SEVERITY_COLOR.get(impact, ("#aaa", "⚪"))

            raw = r.get("raw_source", "").strip()
            raw_source_block = (
                _RAW_SOURCE_BLOCK.format(raw_source=_esc(raw[:3000]))
                if raw else ""
            )

            blocks.append(FINDING_TEMPLATE.format(
                severity_class   = _severity_class(impact),
                severity_emoji   = emoji,
                impact           = impact,
                confidence       = r.get("confidence", "N/A"),
                check            = _esc(r.get("check", "N/A")),
                description      = _esc(r.get("description", "").strip()),
                elements         = _esc(_format_elements(r.get("elements", []))),
                raw_source_block = raw_source_block,
                wiki             = r.get("wiki_url", "#"),
            ))
        findings_html = "\n".join(blocks)

    return HTML_TEMPLATE.format(
        subtitle       = cfg["subtitle"],
        target         = _esc(target),
        domain         = domain.upper(),
        engine         = cfg["engine"],
        date           = now,
        detector_count = detector_count,
        status         = status,
        status_color   = status_color,
        total          = total,
        count_high     = count_high,
        count_medium   = count_med,
        count_low      = count_low,
        references     = cfg["references"],
        findings_html  = findings_html,
    )