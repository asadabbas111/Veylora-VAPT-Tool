"""Professional PDF report generator (ReportLab).

Produces a branded Veylora penetration-testing style report with cover page,
logo, charts, tables, risk ratings, attack paths, MITRE mapping and remediation."""

import hashlib
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape as _xesc

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image, Paragraph, Spacer, Table, TableStyle, PageBreak, SimpleDocTemplate,
)

from app.config import settings
from app.models.ai import AIAnalysis
from app.models.asset import Asset
from app.models.assessment import Assessment, AssessmentScope
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.graph import AttackPath
from app.models.mitre import MitreTechnique
from app.models.remediation import RemediationTask
from app.models.report import ReportRecord
from app.services.mitre_service import coverage_stats

REPORT_DIR = Path(settings.EVIDENCE_DIR) / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Balanced professional palette
INK = colors.HexColor("#0f172a")        # near-black navy - primary text
SLATE = colors.HexColor("#475569")      # muted secondary text
PAPER = colors.HexColor("#ffffff")
MIST = colors.HexColor("#f1f5f9")       # light row/panel fill
SEV_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#1d4ed8"),
    "info": colors.HexColor("#64748b"),
}
BRAND = colors.HexColor("#0d9488")       # teal brand accent
BRAND_DEEP = colors.HexColor("#0f172a")  # navy
LOGO_PATH = Path(__file__).resolve().parents[3] / "frontend" / "public" / "logo.png"
HAS_LOGO = LOGO_PATH.exists()


def _logo_flowable(width_mm: float = 42) -> Image | None:
    if not HAS_LOGO:
        return None
    return Image(str(LOGO_PATH), width=width_mm * mm, height=width_mm * mm)


def _decorate_cover(canvas, doc) -> None:
    """Branding drawn only on the cover page."""
    canvas.saveState()
    w, h = A4
    # top brand band
    canvas.setFillColor(BRAND_DEEP)
    canvas.rect(0, h - 34 * mm, w, 34 * mm, stroke=0, fill=1)
    canvas.setFillColor(BRAND)
    canvas.rect(0, h - 36.5 * mm, w, 2.5 * mm, stroke=0, fill=1)
    # bottom band
    canvas.setFillColor(BRAND_DEEP)
    canvas.rect(0, 0, w, 24 * mm, stroke=0, fill=1)
    canvas.setFillColor(BRAND)
    canvas.rect(0, 24 * mm, w, 2 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(20 * mm, 10 * mm, "Veylora — AI Autonomous Vulnerability Assessment")
    canvas.setFont("Helvetica", 8.5)
    canvas.drawString(20 * mm, 7 * mm, "CONFIDENTIAL — authorized penetration-testing report")
    canvas.restoreState()
    if HAS_LOGO:
        canvas.saveState()
        canvas.drawImage(str(LOGO_PATH), 20 * mm, h - 29.5 * mm, width=18 * mm, height=18 * mm,
                         mask="auto", preserveAspectRatio=True)
        canvas.restoreState()


def _decorate_pages(canvas, doc) -> None:
    """Skyline header + footer on every content page."""
    canvas.saveState()
    w, h = A4
    # header underline
    canvas.setStrokeColor(BRAND)
    canvas.setLineWidth(1.5)
    canvas.line(20 * mm, h - 14 * mm, w - 20 * mm, h - 14 * mm)
    canvas.setStrokeColor(MIST)
    canvas.setLineWidth(0.75)
    canvas.line(20 * mm, 12 * mm, w - 20 * mm, 12 * mm)
    # wordmark
    canvas.setFillColor(BRAND_DEEP)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(20 * mm, h - 11.5 * mm, "Veylora")
    canvas.setFillColor(SLATE)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(20 * mm, h - 9 * mm, "AI Autonomous Vulnerability Assessment & Authorized Penetration Testing")
    # page number
    canvas.setFillColor(SLATE)
    canvas.setFont("Helvetica", 8.5)
    canvas.drawString(w - 30 * mm, 6.5 * mm, f"Page {canvas.getPageNumber()}")
    canvas.drawString(20 * mm, 6.5 * mm, "CONFIDENTIAL — Veylora")
    canvas.restoreState()


def _styles():
    ss = getSampleStyleSheet()
    return {
        "Title": ss["Title"],
        "H1": ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=16, textColor=INK, spaceAfter=12, wordWrap="CJK"),
        "H2": ParagraphStyle("H2", fontName="Helvetica-Bold", fontSize=13, textColor=BRAND_DEEP, spaceAfter=10, spaceBefore=14, wordWrap="CJK"),
        "Body": ParagraphStyle("Body", fontName="Helvetica", fontSize=10, leading=15, textColor=colors.HexColor("#1f2937"), spaceAfter=8, wordWrap="CJK"),
        "Small": ParagraphStyle("Small", fontName="Helvetica", fontSize=8.5, leading=12, textColor=SLATE, wordWrap="CJK"),
        "Cell": ParagraphStyle("Cell", fontName="Helvetica", fontSize=9, leading=12, wordWrap="CJK"),
        "Cover": ParagraphStyle("Cover", fontName="Helvetica-Bold", fontSize=30, leading=36, textColor=BRAND_DEEP, alignment=TA_CENTER),
        "CoverSub": ParagraphStyle("CoverSub", fontName="Helvetica", fontSize=12.5, leading=17, textColor=SLATE, alignment=TA_CENTER),
        "Detail": ParagraphStyle("Detail", fontName="Helvetica", fontSize=10.5, leading=16, textColor=INK),
        "DetailLabel": ParagraphStyle("DetailLabel", fontName="Helvetica-Bold", fontSize=8, leading=12, textColor=BRAND, alignment=TA_LEFT),
    }


def _severity_table(rows: list[list], cols: int, widths: list) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_DEEP),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, MIST]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _esc(value: str | None) -> str:
    """Escape text for ReportLab Paragraph markup."""
    return _xesc(value or "", {"\"": "&quot;", "'": "&#39;"})


def _is_web_finding(f: Finding) -> bool:
    svc = (f.affected_service or "").lower()
    return svc in ("http", "https", "http-proxy") or f.affected_port in (80, 443, 8080)


def _web_endpoint(f: Finding) -> str:
    url = (f.metadata_json or {}).get("url")
    if url:
        return url
    scheme = "https" if f.affected_port == 443 else "http"
    host = (f.asset.ip_address or f.asset.hostname) if f.asset else "-"
    return f"{scheme}://{host}:{f.affected_port or 80}"


def _affected_location(f: Finding) -> str:
    """Human-readable 'where the vulnerability lives' on the target."""
    url = (f.metadata_json or {}).get("url")
    if url:
        return url
    host = (f.asset.ip_address or f.asset.hostname) if f.asset else "-"
    port = f"{host}:{f.affected_port}" if f.affected_port else host
    if f.affected_service:
        return f"{port}/{f.protocol or 'tcp'} ({f.affected_service})"
    return f"{port}/{f.protocol or 'tcp'}" if f.affected_port else host


def _risk_breakdown_text(f: Finding) -> str:
    """Build an explainable 'Risk = ... = score/100' line from the stored breakdown."""
    bd = f.risk_breakdown or {}
    parts = []
    for key in ("cvss", "asset_criticality", "exploitability", "exposure", "confidence", "attack_path"):
        val = bd.get(key)
        if val is not None:
            parts.append(f"{key.replace('_', ' ').title()} +{val}")
    if parts:
        return f"{' + '.join(parts)} = {f.risk_score:.0f}/100"
    return f"Contextual risk score: {f.risk_score:.0f}/100"


def generate_report(db, assessment: Assessment, report_type: str = "full",
                    user_id: int | None = None) -> tuple[str, str, int]:
    """Generate and persist a PDF report. Returns (path, sha256, size)."""
    findings = (
        db.query(Finding).filter(Finding.assessment_id == assessment.id)
        .order_by(Finding.risk_score.desc()).all()
    )
    assets = db.query(Asset).filter(Asset.assessment_id == assessment.id).all()
    scopes = db.query(AssessmentScope).filter(AssessmentScope.assessment_id == assessment.id).all()
    paths = db.query(AttackPath).filter(AttackPath.assessment_id == assessment.id, AttackPath.is_current).all()
    mitigations = coverage_stats(db, assessment.id)
    analyses = {a.finding_id: a for a in db.query(AIAnalysis).filter(AIAnalysis.assessment_id == assessment.id, AIAnalysis.is_final.is_(False)).all()}

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    filename = f"report_assessment_{assessment.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = REPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=22 * mm, rightMargin=22 * mm, topMargin=26 * mm, bottomMargin=22 * mm,
        onFirstPage=_decorate_cover, onLaterPages=_decorate_pages,
    )
    st = _styles()
    story: list = []

    # Cover ---------------------------------------------------------------
    logo = _logo_flowable(46)
    if logo:
        story.append(Spacer(1, 52 * mm))
        story.append(logo)
        story.append(Spacer(1, 10 * mm))
    else:
        story.append(Spacer(1, 70 * mm))
    story.append(Paragraph("Veylora", st["Cover"]))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("AI Autonomous Vulnerability Assessment", st["CoverSub"]))
    story.append(Paragraph("&amp; Authorized Penetration Testing Platform", st["CoverSub"]))
    story.append(Spacer(1, 16 * mm))
    story.append(Paragraph(
        "<font color='#0d9488'><b>PENETRATION-TESTING REPORT</b></font>",
        ParagraphStyle("CoverTag", fontName="Helvetica-Bold", fontSize=12, leading=16,
                       alignment=TA_CENTER, textColor=SLATE),
    ))
    story.append(Spacer(1, 14 * mm))

    detail_rows = [
        ["ASSESSMENT", _esc(assessment.name or "Assessment")],
        ["CLIENT / PROJECT", _esc(assessment.client_name or "Security Operations Lab")],
        ["AUTHORIZED TARGET(S)", (_esc(", ".join(s.target for s in scopes)) or "None defined")],
    ]
    if assessment.start_date:
        detail_rows.append(["ASSESSMENT PERIOD", f"{assessment.start_date} to {assessment.end_date or 'on-going'}"])
    detail_rows.append(["PREPARED", f"{datetime.now().strftime('%d %b %Y, %H:%M')} local ({datetime.utcnow().strftime('%d %b %Y, %H:%M')} UTC)"])
    detail_rows.append(["PREPARED BY", "Veylora — AI Autonomous Vulnerability Assessment & Authorized Penetration Testing Platform"])

    dt_rows = []
    for label, value in detail_rows:
        dt_rows.append([
            Paragraph(label, st["DetailLabel"]),
            Paragraph(value, st["Detail"]),
        ])
    dt = Table(dt_rows, colWidths=[55 * mm, 100 * mm])
    dt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#e2e8f0")),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(dt)
    story.append(Spacer(1, 34 * mm))
    story.append(Paragraph(
        "CONFIDENTIAL — This report contains sensitive findings for authorized use only. "
        "Distribution is limited to the engagement's approved stakeholders.",
        ParagraphStyle("ConfNote", fontName="Helvetica-Oblique", fontSize=8.5, leading=12,
                       textColor=SLATE, alignment=TA_CENTER),
    ))
    story.append(PageBreak())

    # Executive summary ---------------------------------------------------
    story.append(Paragraph("1. Executive Summary", st["H1"]))
    top_risk = max((f.risk_score for f in findings), default=0)
    total_risk = round(sum(f.risk_score for f in findings), 1)
    ai_analyses = [a for a in analyses.values()]
    xsummary = ai_analyses[0].executive_summary if ai_analyses else None
    overview = (
        f"An authorized security assessment was conducted against {len(scopes)} authorized "
        f"scope entit(-y/ies) inside an isolated laboratory network. The platform discovered "
        f"{len(assets)} asset(s), recorded {len(findings)} normalized finding(s) and identified "
        f"{len(paths)} high-risk attack path(s). The peak contextual risk score is {top_risk:.0f}/100."
    )
    story.append(Paragraph(overview, st["Body"]))
    if xsummary:
        story.append(Paragraph("AI Analyst Summary", st["H2"]))
        story.append(Paragraph(xsummary, st["Body"]))
    story.append(PageBreak())

    # Scope + methodology ---------------------------------------------------
    story.append(Paragraph("2. Assessment Scope", st["H1"]))
    scope_rows = [["Target", "Type", "Description"]]
    for s in scopes:
        scope_rows.append([Paragraph(s.target, st["Cell"]), s.target_type, Paragraph(s.description or "-", st["Cell"])])
    if len(scope_rows) > 1:
        story.append(_severity_table(scope_rows, 3, [70 * mm, 30 * mm, 55 * mm]))
    story.append(Paragraph("All active validation was limited to the authorized targets above.", st["Small"]))

    story.append(Paragraph("3. Methodology", st["H1"]))
    story.append(Paragraph(
        "The assessment followed the platform workflow: scope definition and server-side scope validation, "
        "asset discovery, service enumeration, vulnerability scanning, normalization and deduplication, "
        "explainable context-aware risk scoring (CVSS + asset criticality + exploitability + exposure + "
        "confidence + attack-path position), attack-path graph construction, controlled validation with "
        "explicit approval, AI-assisted analysis and prioritization, remediation tracking and re-testing.",
        st["Body"]))
    story.append(Paragraph(f"Rules of engagement: {assessment.rules_of_engagement or 'Restricted to passive/non-destructive checks unless explicitly approved.'}", st["Body"]))
    story.append(PageBreak())

    # Asset inventory ------------------------------------------------------
    story.append(Paragraph("4. Asset Inventory", st["H1"]))
    asset_rows = [["IP", "Hostname", "OS", "Services", "Risk", "Criticality"]]
    for a in assets:
        svc = ", ".join(f"{s.service_name}:{s.port}" for s in a.services[:8]) or "-"
        asset_rows.append([
            Paragraph(a.ip_address or "-", st["Cell"]), Paragraph(a.hostname or "-", st["Cell"]),
            f"{a.os_name or 'Unknown'}", Paragraph(svc, st["Cell"]),
            f"{a.risk_score:.1f}", f"{a.criticality:.1f}",
        ])
    story.append(_severity_table(asset_rows, 6, [40 * mm, 40 * mm, 25 * mm, 40 * mm, 15 * mm, 15 * mm]))
    story.append(PageBreak())

    # Risk summary ---------------------------------------------------------
    story.append(Paragraph("5. Risk Summary", st["H1"]))
    story.append(Paragraph(
        f"Total findings: {len(findings)}. Aggregate risk (sum of per-finding contextual scores): {total_risk:.1f}.",
        st["Body"]))
    severity_rows = [["Severity", "Count", "Min Risk", "Max Risk", "Avg Risk"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        severity_rows.append([
            sev.capitalize(), str(len(group)), f"{min(f.risk_score for f in group):.0f}",
            f"{max(f.risk_score for f in group):.0f}", f"{sum(f.risk_score for f in group)/len(group):.1f}",
        ])
    story.append(_severity_table(severity_rows, 5, [35 * mm, 25 * mm, 30 * mm, 30 * mm, 35 * mm]))
    if report_type in ("full", "technical"):
        story.append(Paragraph("Risk equation", st["H2"]))
        story.append(Paragraph(
            "Score = CVSS(≤40) + Asset Criticality(≤15) + Exploitability(≤10) + Exposure(≤20) + "
            "Confidence(≤5) + Attack Path(≤10), reduced by the false-positive penalty, clamped to 0-100. "
            "Severity bands: 0-19 Info, 20-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical.",
            st["Body"]))
    story.append(PageBreak())

    # Web application findings (HTTP + HTTPS) --------------------------------
    web_findings = [f for f in findings if _is_web_finding(f)]
    story.append(Paragraph(f"6. Web Application Findings — HTTP &amp; HTTPS ({len(web_findings)})", st["H1"]))
    if web_findings:
        story.append(Paragraph(
            "Vulnerabilities found on the web application surface (ports 80, 443 and web-management "
            "ports) are reported below with the exact endpoint, proof, risk breakdown and remediation.",
            st["Body"]))
        web_rows = [["Endpoint", "Title", "Severity", "CVSS", "Risk"]]
        for f in sorted(web_findings, key=lambda x: x.risk_score, reverse=True)[:40]:
            web_rows.append([
                Paragraph(_esc(_web_endpoint(f)), st["Cell"]),
                Paragraph(_esc(f.title), st["Cell"]),
                f.severity.capitalize(), f"{f.cvss_score or '-'}", f"{f.risk_score:.0f}",
            ])
        story.append(_severity_table(web_rows, 5, [60 * mm, 55 * mm, 22 * mm, 15 * mm, 15 * mm]))

        for f in sorted(web_findings, key=lambda x: x.risk_score, reverse=True)[:15]:
            story.append(Paragraph(f"<b>{_esc(f.title)}</b>", st["H2"]))
            story.append(Paragraph(
                f"<b>Affected endpoint:</b> {_esc(_web_endpoint(f))}<br/>"
                f"<b>Severity:</b> {f.severity.capitalize()} &nbsp;|&nbsp; <b>CVSS:</b> {f.cvss_score or 'n/a'} "
                f"(vector: {_esc(f.cvss_vector) or 'not scored'}) &nbsp;|&nbsp; <b>Confidence:</b> {f.confidence:.0f}%",
                st["Body"]))
            story.append(Paragraph(f"<b>Risk analysis:</b> {_esc(_risk_breakdown_text(f))}", st["Body"]))
            story.append(Paragraph(_esc(f.description or "No description provided."), st["Body"]))
            refs = [x for x in (f.cve, f.cwe) if x]
            mitre = [t.technique_id for t in (f.mitre_techniques or [])]
            story.append(Paragraph(
                f"<b>References:</b> {', '.join(refs) or 'n/a'}"
                f"&nbsp;|&nbsp; <b>MITRE ATT&amp;CK:</b> {', '.join(mitre) or 'n/a'}",
                st["Small"]))
            evidence = [e.content for e in (f.evidence or []) if e.content][:2]
            if evidence:
                story.append(Paragraph("<b>Proof:</b> " + " | ".join(_esc(e) for e in evidence), st["Small"]))
            if f.remediation:
                story.append(Paragraph(f"<b>Recommended fix:</b> {_esc(f.remediation)}", st["Body"]))
        story.append(Paragraph(
            f"{len(web_findings)} of {len(findings)} findings are web-application issues ({'HTTPS' if any(f.affected_port == 443 for f in web_findings) else 'HTTP-only'} surface covered).",
            st["Small"]))
    else:
        story.append(Paragraph("No web-application findings detected on HTTP/HTTPS endpoints.", st["Body"]))
    story.append(PageBreak())

    # Findings by severity -------------------------------------------------
    for sev in ("critical", "high", "medium", "low", "info"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        story.append(Paragraph(f"7.{_sev_index(sev)} {sev.capitalize()} Findings ({len(group)})", st["H1"]))
        for f in group[:30]:
            story.append(Paragraph(f"{f.cve or ''} {_esc(f.title)}", st["H2"]))
            story.append(Paragraph(
                f"<b>Affected location:</b> {_esc(_affected_location(f))}  |  "
                f"<b>Risk:</b> {f.risk_score:.0f}/100  |  <b>CVSS:</b> {f.cvss_score or 'n/a'}  |  "
                f"<b>Severity:</b> {f.severity.capitalize()}  |  <b>Confidence:</b> {f.confidence:.0f}%  |  "
                f"<b>Status:</b> {f.status}",
                st["Small"]))
            story.append(Paragraph(f"<b>Vector:</b> {_esc(f.cvss_vector) or 'not scored'}", st["Small"]))
            story.append(Paragraph(_esc(f.description or ""), st["Body"]))
            if f.cve or f.cwe:
                story.append(Paragraph(f"References: {', '.join(x for x in [f.cve, f.cwe] if x)}", st["Small"]))
            ai = analyses.get(f.id)
            if ai and ai.recommended_remediation:
                story.append(Paragraph(f"<b>Recommended fix:</b> {_esc(ai.recommended_remediation)}", st["Body"]))
        story.append(PageBreak())

    # Attack paths ---------------------------------------------------------
    story.append(Paragraph(f"8. Attack-Path Analysis ({len(paths)})", st["H1"]))
    if paths:
        path_rows = [["Path", "Length", "Cum. Risk", "Confidence", "Vulns"]]
        for p in paths:
            path_rows.append([
                Paragraph(p.name, st["Cell"]), str(p.path_length), f"{p.cumulative_risk:.1f}",
                f"{p.confidence:.0f}%", str(p.vulnerability_count),
            ])
        story.append(_severity_table(path_rows, 5, [90 * mm, 20 * mm, 25 * mm, 25 * mm, 15 * mm]))
        story.append(Paragraph("The most valuable path:", st["H2"]))
        top = max(paths, key=lambda p: p.cumulative_risk)
        steps = " → ".join(str(n.get("label")) for n in (top.nodes_json or []))
        story.append(Paragraph(steps, st["Body"]))
    story.append(PageBreak())

    # MITRE -----------------------------------------------------------------
    story.append(Paragraph("9. MITRE ATT&amp;CK Coverage", st["H1"]))
    mitre_rows = [["Technique", "Name", "Tactic"]]
    for f in findings:
        for t in f.mitre_techniques or []:
            mitre_rows.append([t.technique_id, t.name, t.tactic])
    # dedupe
    seen_m = set()
    dedup = [mitre_rows[0]]
    for r in mitre_rows[1:]:
        if r[0] not in seen_m:
            seen_m.add(r[0]); dedup.append(r)
    story.append(_severity_table(dedup if len(dedup) > 1 else mitre_rows, 3, [25 * mm, 80 * mm, 50 * mm]))
    story.append(Paragraph(
        f"Coverage: {mitigations['technique_count']} technique(s), {mitigations['tactic_count']} tactic(s), "
        f"{mitigations['coverage_percentage']}% of the reference technique catalogue.",
        st["Body"]))
    story.append(PageBreak())

    # Evidence ----------------------------------------------------------------
    story.append(Paragraph("10. Evidence", st["H1"]))
    evidence = db.query(Evidence).filter(Evidence.assessment_id == assessment.id).limit(60).all()
    ev_rows = [["ID", "Category", "Source", "SHA-256"]]
    for e in evidence:
        ev_rows.append([str(e.id), e.category, Paragraph(e.source or "-", st["Cell"]), e.sha256[:16]])
    story.append(_severity_table(ev_rows, 4, [15 * mm, 30 * mm, 40 * mm, 70 * mm]))
    story.append(Paragraph("All evidence is content-addressed (SHA-256) and immutable after assessment completion.", st["Small"]))
    story.append(PageBreak())

    # Remediation plan ----------------------------------------------------------
    story.append(Paragraph("11. Remediation Plan", st["H1"]))
    tasks = db.query(RemediationTask).filter(RemediationTask.assessment_id == assessment.id).all()
    if tasks:
        rem_rows = [["Finding", "Assignee", "Deadline", "Status", "Before → After"]]
        for t in tasks:
            f = db.get(Finding, t.finding_id)
            rem_rows.append([
                Paragraph(f.title[:60] if f else f"finding {t.finding_id}", st["Cell"]),
                t.assignee_name or "-", str(t.deadline or "-"), t.status,
                f"{t.retest_before_score or '-'} → {t.retest_after_score or '-'}",
            ])
        story.append(_severity_table(rem_rows, 5, [60 * mm, 30 * mm, 25 * mm, 25 * mm, 25 * mm]))
    else:
        story.append(Paragraph("No remediation tasks registered yet; the findings above govern the fix queue.", st["Body"]))
    story.append(PageBreak())

    # Timeline ---------------------------------------------------------------
    story.append(Paragraph("12. Assessment Timeline", st["H1"]))
    stage_log = assessment.stage_log or {}
    time_rows = [["Stage", "Status", "Started"]]
    for stage in ("asset_discovery", "service_enumeration", "vulnerability_scan", "vulnerability_normalization",
                  "risk_calculation", "attack_path_analysis", "ai_analysis", "validation", "report_generation"):
        entry = stage_log.get(stage, {})
        time_rows.append([stage.replace("_", " ").title(), entry.get("status", "-"),
                          (entry.get("started_at") or "-")[:19]])
    story.append(_severity_table(time_rows, 3, [50 * mm, 35 * mm, 60 * mm]))
    story.append(Paragraph("Generated by Veylora — AI Autonomous Vulnerability Assessment &amp; Authorized Penetration Testing Platform.", st["Small"]))

    doc.build(story)

    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    record = ReportRecord(
        assessment_id=assessment.id,
        report_type=report_type,
        file_path=str(path.resolve()),
        file_sha256=sha,
        file_size=len(data),
        generated_by=user_id or assessment.owner_id or 1,
    )
    db.add(record)
    db.commit()
    return str(path.resolve()), sha, len(data)


def _sev_index(sev: str) -> str:
    return {"critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"}.get(sev, "6")