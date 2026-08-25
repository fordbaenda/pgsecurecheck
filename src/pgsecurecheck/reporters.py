from __future__ import annotations

import json
from hashlib import sha256
from html import escape
from typing import Any

from rich.console import Console
from rich.table import Table

from pgsecurecheck.models import ScanReport

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_console(report: ScanReport, console: Console) -> None:
    table = Table(title="pgSecureCheck findings")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Finding")
    for finding in report.findings:
        table.add_row(
            finding.severity.value.upper(),
            finding.check_id,
            finding.resource,
            finding.title,
        )
    console.print(table)
    console.print(
        f"[bold]{len(report.findings)} finding(s)[/bold], "
        f"{len(report.skipped_checks)} check(s) skipped"
    )


def render_json(report: ScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def render_html(report: ScanReport) -> str:
    """Render a self-contained, printable HTML security report."""
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    for finding in report.findings:
        counts[finding.severity.value] += 1

    high_cards: list[str] = []
    other_rows: list[str] = []
    for finding in report.findings:
        evidence = escape(json.dumps(finding.evidence, indent=2, sort_keys=True, default=str))
        references = "".join(
            f'<li><a href="{escape(reference, quote=True)}">{escape(reference)}</a></li>'
            for reference in finding.references
            if reference.startswith(("https://", "http://"))
        )
        reference_block = f'<ul class="references">{references}</ul>' if references else ""
        severity = finding.severity.value
        if severity in {"critical", "high"}:
            high_cards.append(
                f"""
            <article class="finding">
              <div class="finding-head">
                <div><h3>{escape(finding.title)}</h3>
                <div class="identity">{escape(finding.check_id)} · {escape(finding.category)} ·
                  <code>{escape(finding.resource)}</code></div></div>
                <span class="badge {severity}">{severity.upper()}</span>
              </div>
              <p><strong>Öneri:</strong> {escape(finding.recommendation)}</p>
              <details><summary>Kanıtı göster</summary><pre>{evidence}</pre></details>
              {reference_block}
            </article>"""
            )
        else:
            other_rows.append(
                f'<tr><td><span class="badge {severity}">{severity.upper()}</span></td>'
                f"<td>{escape(finding.check_id)}</td><td><strong>{escape(finding.title)}</strong>"
                f'<div class="table-note">{escape(finding.recommendation)}</div></td>'
                f"<td><code>{escape(finding.resource)}</code></td></tr>"
            )

    categories = {finding.category for finding in report.findings}
    priorities: list[tuple[str, str]] = []
    if categories & {"authentication", "network"}:
        priorities.append(
            (
                "Kimlik doğrulama ve ağ kurallarını doğrula",
                "HBA kapsamını daralt; TLS ve SCRAM geçişini kontrollü biçimde planla.",
            )
        )
    if "privileges" in categories:
        priorities.append(
            (
                "Yüksek yetkili rolleri gözden geçir",
                "Superuser ve yönetici yetkilerini iş gereksinimleriyle karşılaştır.",
            )
        )
    if "audit" in categories:
        priorities.append(
            (
                "Denetim yapılandırmasını doğrula",
                "pgAudit preload, extension ve politika ayarlarının tutarlılığını kontrol et.",
            )
        )
    if "logging" in categories:
        priorities.append(
            (
                "Loglama kapsamını tamamla",
                "Bağlantı yaşam döngüsü ve denetim kimliği alanlarını kurum politikasına uyarla.",
            )
        )
    if not priorities and report.findings:
        priorities.append(
            (
                "Bulguları doğrula ve önceliklendir",
                "Değişiklik yapmadan önce kanıtları sistem sahipleriyle birlikte incele.",
            )
        )
    priority_html = "".join(
        f'<div class="priority"><b>{index}</b><div><strong>{escape(title)}</strong><br>'
        f"{escape(description)}</div></div>"
        for index, (title, description) in enumerate(priorities[:4], start=1)
    )

    skipped_rows = "".join(
        f"<tr><td>{escape(check_id)}</td><td>{escape(reason)}</td></tr>"
        for check_id, reason in sorted(report.skipped_checks.items())
    )
    skipped_section = (
        f'<section class="panel"><h2>Atlanan kontroller</h2><table>'
        f"<thead><tr><th>Kontrol</th><th>Neden</th></tr></thead>"
        f"<tbody>{skipped_rows}</tbody></table></section>"
        if skipped_rows
        else ""
    )
    high_findings_html = "".join(high_cards) or (
        '<div class="empty">Kritik veya yüksek önem seviyeli bulgu tespit edilmedi.</div>'
    )
    other_findings_html = "".join(other_rows)
    other_section = (
        '<section class="panel"><h2>Diğer bulgular</h2><div class="table-wrap"><table>'
        "<thead><tr><th>Seviye</th><th>Kontrol</th><th>Bulgu ve öneri</th>"
        f"<th>Kaynak</th></tr></thead><tbody>{other_findings_html}</tbody></table></div></section>"
        if other_findings_html
        else ""
    )
    summary_text = (
        f"Tarama sonucunda {len(report.findings)} bulgu tespit edildi. "
        f"Bunların {counts['critical'] + counts['high']} tanesi kritik veya yüksek önem "
        "seviyesindedir. Değişikliklerden önce bulguların kanıtları, uygulama bağımlılıkları "
        "ve izinli erişim kaynakları doğrulanmalıdır."
        if report.findings
        else "Tarama tamamlandı ve raporlanabilir güvenlik bulgusu tespit edilmedi."
    )

    return f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(report.tool)} Güvenlik Değerlendirmesi</title>
  <style>
    :root{{--ink:#172033;--muted:#667085;--line:#e4e7ec;--paper:#fff;--bg:#f4f6f9;
      --critical:#7a271a;--high:#b42318;--medium:#b54708;--low:#175cd3;--info:#475467}}
    *{{box-sizing:border-box}} body{{margin:0;color:var(--ink);background:var(--bg);
      font:15px/1.55 Inter,Segoe UI,Arial,sans-serif}} .page{{width:min(1120px,calc(100% - 32px));
      margin:32px auto 64px}} header{{padding:38px;color:#fff;border-radius:18px;
      background:linear-gradient(135deg,#101828,#173a5e);box-shadow:0 16px 40px #10182822}}
    .brand{{color:#7cd4fd;font-weight:800;letter-spacing:.08em;text-transform:uppercase}}
    h1{{margin:10px 0 6px;font-size:34px;line-height:1.2}} header p{{margin:0;color:#d0d5dd}}
    .meta{{display:flex;flex-wrap:wrap;gap:20px;margin-top:25px;color:#eaecf0;font-size:13px}}
    .grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}}
    .card,.panel{{background:var(--paper);border:1px solid var(--line);border-radius:14px;
      box-shadow:0 3px 12px #1018280a}} .card{{padding:20px}} .card strong{{display:block;
      margin-top:5px;font-size:30px}} .card span,.identity{{color:var(--muted);font-size:12px}}
    .card.high strong,.card.critical strong{{color:var(--high)}}
    .card.medium strong{{color:var(--medium)}}
    .card.low strong{{color:var(--low)}} .panel{{padding:26px;margin-top:18px}}
    h2{{margin:0 0 16px;font-size:21px}} .finding{{padding:20px 0;border-top:1px solid var(--line)}}
    .finding:first-of-type{{border-top:0;padding-top:0}} .finding-head{{display:flex;
      align-items:flex-start;justify-content:space-between;gap:16px}}
    .finding h3{{margin:0 0 4px;font-size:16px}}
    .badge{{flex:none;padding:4px 10px;border-radius:99px;font-size:11px;font-weight:800}}
    .badge.critical,.badge.high{{color:#912018;background:#fee4e2}}
    .badge.medium{{color:#93370d;background:#fef0c7}}
    .badge.low{{color:#1849a9;background:#dbeafe}} .badge.info{{color:#344054;background:#eaecf0}}
    code{{padding:2px 5px;background:#f2f4f7;border-radius:4px}} details{{margin-top:12px}}
    summary{{cursor:pointer;color:#175cd3;font-weight:600}}
    pre{{overflow:auto;padding:14px;border-radius:8px;
      background:#101828;color:#d0d5dd;font:12px/1.5 Consolas,monospace}}
    .references{{padding-left:20px}}
    a{{color:#175cd3;overflow-wrap:anywhere}} table{{width:100%;border-collapse:collapse}}
    th,td{{padding:11px 10px;text-align:left;border-bottom:1px solid var(--line);
      vertical-align:top}}
    th{{color:var(--muted);font-size:12px;text-transform:uppercase}}
    .table-note{{margin-top:4px;color:var(--muted);font-size:13px}}
    .table-wrap{{overflow-x:auto}}
    .notice{{padding:14px 16px;border-left:4px solid var(--medium);border-radius:8px;
      background:#fffaeb}}
    .priority{{display:grid;grid-template-columns:32px 1fr;gap:12px;margin:14px 0}}
    .priority b{{display:grid;place-items:center;width:30px;height:30px;color:white;
      border-radius:50%;background:#175cd3}}
    .empty{{padding:28px;text-align:center;color:#067647;background:#ecfdf3;border-radius:10px}}
    footer{{margin-top:22px;color:var(--muted);
      font-size:12px;text-align:center}}
    @media(max-width:760px){{.grid{{grid-template-columns:repeat(2,1fr)}}header{{padding:25px}}
      h1{{font-size:27px}}.panel{{padding:20px}}}}
    @media print{{body{{background:white}}.page{{width:100%;margin:0}}
      header,.card,.panel{{box-shadow:none}}
      .finding,.priority{{break-inside:avoid}}details:not([open]) pre{{display:none}}}}
  </style>
</head>
<body><main class="page">
  <header><div class="brand">{escape(report.tool)}</div><h1>PostgreSQL Güvenlik Değerlendirmesi</h1>
    <p>Salt okunur güvenlik duruşu taraması</p><div class="meta">
    <span>Sunucu: {escape(report.server_version)}</span>
    <span>Araç sürümü: {escape(report.version)}</span>
    <span>Toplam bulgu: {len(report.findings)}</span></div></header>
  <section class="grid" aria-label="Özet">
    <div class="card high"><span>Kritik / Yüksek önem</span>
      <strong>{counts["critical"] + counts["high"]}</strong></div>
    <div class="card medium"><span>Orta</span><strong>{counts["medium"]}</strong></div>
    <div class="card low"><span>Düşük / Bilgi</span>
      <strong>{counts["low"] + counts["info"]}</strong></div>
    <div class="card"><span>Atlanan kontrol</span>
      <strong>{len(report.skipped_checks)}</strong></div>
  </section>
  <section class="panel"><h2>Yönetici özeti</h2><p>{escape(summary_text)}</p>
    <div class="notice"><strong>Not:</strong> Bu rapor karar desteği sağlar; tek başına
      uyumluluk kanıtı veya otomatik düzeltme talimatı değildir.</div></section>
  <section class="panel"><h2>Önerilen aksiyon sırası</h2>{priority_html}</section>
  <section class="panel"><h2>Kritik ve yüksek önem seviyeli bulgular</h2>
    {high_findings_html}</section>
  {other_section}
  {skipped_section}
  <footer>{escape(report.tool)} {escape(report.version)} ·
    Bu rapor karar desteği sağlar; uyumluluk kanıtı değildir.</footer>
</main></body></html>"""


def render_sarif(report: ScanReport) -> str:
    """Render findings as SARIF 2.1.0 for GitHub Code Scanning."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        rules.setdefault(
            finding.check_id,
            {
                "id": finding.check_id,
                "name": finding.check_id.replace("-", "_"),
                "shortDescription": {"text": finding.title},
                "help": {
                    "text": finding.recommendation,
                    "markdown": finding.recommendation,
                },
                "properties": {
                    "category": finding.category,
                    "defaultSeverity": finding.severity.value,
                    "references": finding.references,
                },
            },
        )
        fingerprint_source = f"{finding.check_id}\0{finding.resource}"
        fingerprint = sha256(fingerprint_source.encode()).hexdigest()
        results.append(
            {
                "ruleId": finding.check_id,
                "level": _SARIF_LEVELS[finding.severity.value],
                "message": {
                    "text": f"{finding.title}. {finding.recommendation}",
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": finding.resource,
                                "kind": finding.category,
                            }
                        ]
                    }
                ],
                "partialFingerprints": {"pgSecureCheck/v1": fingerprint},
                "properties": {
                    "severity": finding.severity.value,
                    "resource": finding.resource,
                    "evidence": finding.evidence,
                },
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": report.version,
                        "informationUri": "https://github.com/fordbaenda/pgsecurecheck",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": "pgsecurecheck/"},
                "results": results,
                "properties": {
                    "serverVersion": report.server_version,
                    "skippedChecks": report.skipped_checks,
                },
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True)
