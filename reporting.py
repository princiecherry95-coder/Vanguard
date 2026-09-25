"""Offline multi-format SOC reporting. No network dependencies."""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any
import json

import pandas as pd


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:80] or "vanguard_report"


def report_context(rows: list[dict[str, Any]], analysis: dict[str, Any] | None, source: str) -> dict[str, Any]:
    from analytics import summary
    s = summary(rows)
    return {
        "system": "Vanguard-SIEM",
        "classification": "LOCAL DEFENSIVE ANALYTICS",
        "source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analytics": s,
        "risk_score": (analysis or {}).get("risk_score", 0),
        "raw_alerts": len((analysis or {}).get("alerts", [])),
        "finding_groups": len((analysis or {}).get("analyst_alerts", [])),
        "incidents": len((analysis or {}).get("incidents", [])),
        "parse_coverage": (analysis or {}).get("parse_coverage", 0),
        "evidence_sha256": (analysis or {}).get("evidence_sha256", ""),
        "first_seen": s.get("first_seen"),
        "last_seen": s.get("last_seen"),
        "data_state": "SIMULATED / DEMO" if source.lower().find("demo") >= 0 else "OBSERVED LOCAL EVIDENCE",
    }


def make_pdf(rows, analysis, source, title="Vanguard-SIEM SOC Analytics Report") -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ctx = report_context(rows, analysis, source)
    s = ctx["analytics"]
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=14 * mm, leftMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph(title, styles["Title"]),
        Paragraph(f"Data state: {ctx['data_state']}<br/>Source: {source}<br/>Observed window: {ctx.get('first_seen') or 'not available'} → {ctx.get('last_seen') or 'not available'}<br/>Generated: {ctx['generated_at']}<br/>Evidence SHA-256: {ctx.get('evidence_sha256') or 'not supplied'}", styles["Normal"]),
        Spacer(1, 8),
    ]
    metrics = [
        ["Metric", "Value"], ["Records", s["records"]], ["Unique sources", s["unique_sources"]],
        ["Unique targets", s["unique_targets"]], ["Alert rate", f"{s['alert_rate_pct']}%"],
        ["Critical rate", f"{s['critical_rate_pct']}%"], ["Parse coverage", f"{ctx['parse_coverage']}%"],
        ["Risk score", ctx["risk_score"]], ["Raw alerts", ctx["raw_alerts"]],
        ["Analyst finding groups", ctx["finding_groups"]], ["Incidents", ctx["incidents"]],
    ]
    story.append(Table(metrics, repeatRows=1))
    story += [Spacer(1, 10), Paragraph("Severity distribution", styles["Heading2"])]
    story.append(Table([["Severity", "Count"]] + [[k, v] for k, v in s["severity_counts"].items()], repeatRows=1))
    sev_fig = plt.figure(figsize=(6.8, 2.4)); sev_ax = sev_fig.add_subplot(111)
    sev_ax.bar(list(s["severity_counts"].keys()), list(s["severity_counts"].values()))
    sev_ax.set_title("Observed severity distribution"); sev_ax.set_ylabel("Events"); sev_ax.grid(axis="y", alpha=0.2)
    sev_img = BytesIO(); sev_fig.savefig(sev_img, format="png", dpi=140, bbox_inches="tight"); plt.close(sev_fig); sev_img.seek(0)
    story += [Spacer(1, 6), Image(sev_img, width=175 * mm, height=58 * mm)]
    story += [Spacer(1, 10), Paragraph("Top attack types", styles["Heading2"])]
    story.append(Table([["Attack type", "Count"]] + [[str(k), v] for k, v in s["top_attack_types"].items()], repeatRows=1))

    tr = __import__("analytics").trend(rows)
    if not tr.empty:
        fig = plt.figure(figsize=(7.0, 2.5))
        ax = fig.add_subplot(111)
        ax.plot(tr["period"], tr["records"], label="Records")
        ax.plot(tr["period"], tr["alerts"], label="Alerts")
        ax.set_title("Evidence volume and alert trend")
        ax.legend()
        ax.grid(alpha=0.2)
        fig.autofmt_xdate()
        image = BytesIO()
        fig.savefig(image, format="png", dpi=140, bbox_inches="tight")
        plt.close(fig)
        image.seek(0)
        story += [Spacer(1, 8), Paragraph("Trend", styles["Heading2"]), Image(image, width=175 * mm, height=62 * mm)]

    findings = __import__("analytics").findings_dataframe(analysis)
    if not findings.empty:
        story += [Spacer(1, 8), Paragraph("Analyst findings", styles["Heading2"])]
        data = [["ID", "Rule", "Severity", "Confidence", "Count"]]
        data += [[str(r.alert_id), str(r.rule_id), str(r.severity), str(r.confidence), str(r["count"])] for _, r in findings.head(100).iterrows()]
        story.append(Table(data, repeatRows=1, style=TableStyle([("GRID", (0, 0), (-1, -1), .25, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 7)])))

    story += [PageBreak(), Paragraph("Evidence sample (first 500 records)", styles["Heading2"])]
    data = [["Event ID", "Time", "Severity", "Source", "Attack type"]]
    for r in rows[:500]:
        data.append([str(r.get("event_id", "")), str(r.get("timestamp", "")), str(r.get("severity", "")), str(r.get("source_ip", "")), str(r.get("attack_type", ""))[:70]])
    story.append(Table(data, repeatRows=1, style=TableStyle([("GRID", (0, 0), (-1, -1), .25, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 6), ("VALIGN", (0, 0), (-1, -1), "TOP")])))

    doc.build(story)
    return out.getvalue()


def make_docx(rows, analysis, source, title="Vanguard-SIEM SOC Analytics Report") -> bytes:
    from docx import Document
    from docx.shared import Inches
    ctx = report_context(rows, analysis, source)
    s = ctx["analytics"]
    d = Document()
    d.add_heading(title, 0)
    d.add_paragraph(f"Source: {source}\nGenerated: {ctx['generated_at']}\nEvidence SHA-256: {ctx.get('evidence_sha256') or 'not supplied'}")
    d.add_heading("Executive analytics", 1)
    table = d.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    table.rows[0].cells[0].text, table.rows[0].cells[1].text = "Metric", "Value"
    for k, v in [
        ("Records", s["records"]), ("Unique sources", s["unique_sources"]), ("Unique targets", s["unique_targets"]),
        ("Alert rate", f"{s['alert_rate_pct']}%"), ("Critical rate", f"{s['critical_rate_pct']}%"),
        ("Parse coverage", f"{ctx['parse_coverage']}%"), ("Risk score", ctx["risk_score"]),
        ("Raw alerts", ctx["raw_alerts"]), ("Analyst finding groups", ctx["finding_groups"]), ("Incidents", ctx["incidents"]),
    ]:
        cells = table.add_row().cells
        cells[0].text, cells[1].text = k, str(v)
    d.add_heading("Severity distribution", 1)
    for k, v in s["severity_counts"].items():
        d.add_paragraph(f"{k}: {v}")
    d.add_heading("Top attack types", 1)
    for k, v in s["top_attack_types"].items():
        d.add_paragraph(f"{k}: {v}")
    findings = __import__("analytics").findings_dataframe(analysis)
    if not findings.empty:
        d.add_heading("Analyst findings", 1)
        t = d.add_table(rows=1, cols=5); t.style = "Table Grid"
        for cell, h in zip(t.rows[0].cells, ["ID", "Rule", "Severity", "Confidence", "Count"]): cell.text = h
        for _, row in findings.head(100).iterrows():
            cells = t.add_row().cells
            for cell, value in zip(cells, [row.alert_id, row.rule_id, row.severity, row.confidence, row["count"]]): cell.text = str(value)
    d.add_heading("Evidence sample (first 500 records)", 1)
    t = d.add_table(rows=1, cols=5); t.style = "Table Grid"
    for cell, h in zip(t.rows[0].cells, ["Event ID", "Time", "Severity", "Source", "Attack"]): cell.text = h
    for r in rows[:500]:
        cells = t.add_row().cells
        for cell, value in zip(cells, [r.get("event_id", ""), r.get("timestamp", ""), r.get("severity", ""), r.get("source_ip", ""), r.get("attack_type", "")]): cell.text = str(value)[:100]
    out = BytesIO(); d.save(out); return out.getvalue()


def make_xlsx(rows, analysis, source) -> bytes:
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, LineChart, Reference
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.page import PageMargins

    ctx = report_context(rows, analysis, source)
    s = ctx["analytics"]
    wb = Workbook()
    header_fill = PatternFill("solid", fgColor="17212B")
    header_font = Font(bold=True, color="FFFFFF")
    thin = Side(style="thin", color="B7C0C8")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    def style_sheet(ws, landscape=False, repeat_header=True):
        ws.freeze_panes = "A2"
        ws.sheet_view.showGridLines = False
        if ws.max_row:
            for cell in ws[1]:
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
                cell.border = border
            ws.auto_filter.ref = ws.dimensions
        for row in ws.iter_rows():
            for cell in row:
                cell.border = border
                cell.alignment = Alignment(vertical="top", wrap_text=True)
        for col in range(1, ws.max_column + 1):
            values = [str(ws.cell(row=r, column=col).value or "") for r in range(1, min(ws.max_row, 101) + 1)]
            width = min(60, max(12, max((len(v) for v in values), default=12) + 2))
            ws.column_dimensions[get_column_letter(col)].width = width
        ws.sheet_properties.pageSetUpPr.fitToPage = True
        ws.page_setup.fitToWidth = 1
        ws.page_setup.fitToHeight = 0
        ws.page_setup.orientation = "landscape" if landscape else "portrait"
        ws.page_setup.paperSize = ws.PAPERSIZE_A4
        ws.page_margins = PageMargins(left=0.25, right=0.25, top=0.5, bottom=0.5, header=0.2, footer=0.2)
        ws.print_title_rows = "1:1" if repeat_header else None
        ws.oddFooter.center.text = "VANGUARD SOC • Page &P of &N"
        ws.oddFooter.right.text = "Generated: " + str(ctx["generated_at"])

    ws = wb.active
    ws.title = "Executive Summary"
    metrics = [
        ("System", ctx["system"]), ("Classification", ctx["classification"]), ("Source", source),
        ("Generated", ctx["generated_at"]), ("Observed window", f"{ctx.get('first_seen') or 'N/A'} → {ctx.get('last_seen') or 'N/A'}"),
        ("Data state", ctx["data_state"]), ("Evidence SHA-256", ctx.get("evidence_sha256", "")),
        ("Records", s["records"]), ("Unique sources", s["unique_sources"]), ("Unique targets", s["unique_targets"]),
        ("Alert rate %", s["alert_rate_pct"]), ("Critical rate %", s["critical_rate_pct"]),
        ("Parse coverage %", ctx["parse_coverage"]), ("Risk score", ctx["risk_score"]),
        ("Raw alerts", ctx["raw_alerts"]), ("Finding groups", ctx["finding_groups"]), ("Incidents", ctx["incidents"]),
    ]
    ws.append(["Metric", "Value"])
    for k, v in metrics:
        ws.append([k, v])
    style_sheet(ws)

    sev = wb.create_sheet("Severity")
    sev.append(["Severity", "Count"])
    for k, v in s["severity_counts"].items():
        sev.append([k, v])
    chart = BarChart()
    chart.title = "Severity distribution"
    chart.y_axis.title = "Events"
    chart.add_data(Reference(sev, min_col=2, min_row=1, max_row=1 + len(s["severity_counts"])), titles_from_data=True)
    chart.set_categories(Reference(sev, min_col=1, min_row=2, max_row=1 + len(s["severity_counts"])))
    sev.add_chart(chart, "D2")
    style_sheet(sev)

    attacks = wb.create_sheet("Attack Types")
    attacks.append(["Attack type", "Count"])
    for k, v in s["top_attack_types"].items():
        attacks.append([str(k), v])
    style_sheet(attacks)

    sources = wb.create_sheet("Top Sources")
    sources.append(["Source IP", "Events"])
    for k, v in s["top_sources"].items():
        sources.append([str(k), v])
    style_sheet(sources)

    trend = __import__("analytics").trend(rows)
    trws = wb.create_sheet("Trend")
    trws.append(["Period", "Records", "Alerts", "Critical"])
    for _, row in trend.iterrows():
        period = row["period"].to_pydatetime().replace(tzinfo=None)
        trws.append([period, int(row["records"]), int(row["alerts"]), int(row["critical"])])
    if trws.max_row > 1:
        line = LineChart()
        line.title = "Evidence and alert trend"
        line.y_axis.title = "Count"
        line.add_data(Reference(trws, min_col=2, max_col=4, min_row=1, max_row=trws.max_row), titles_from_data=True)
        line.set_categories(Reference(trws, min_col=1, min_row=2, max_row=trws.max_row))
        trws.add_chart(line, "F2")
    style_sheet(trws, landscape=True)

    findings = __import__("analytics").findings_dataframe(analysis)
    fws = wb.create_sheet("Analyst Findings")
    if not findings.empty:
        fws.append(list(findings.columns))
        for row in findings.itertuples(index=False):
            fws.append(list(row))
    else:
        fws.append(["No analyst findings"])
    style_sheet(fws, landscape=True)

    # Preserve every parsed field for every evidence record. No 500-row truncation and no
    # fixed-column projection: the workbook remains a lossless tabular export of the
    # in-memory evidence records.
    ev = wb.create_sheet("Evidence")
    all_columns = []
    seen = set()
    for record in rows:
        for key in record:
            key = str(key)
            if key not in seen:
                seen.add(key)
                all_columns.append(key)
    if all_columns:
        ev.append(all_columns)
        for record in rows:
            ev.append([record.get(column, "") for column in all_columns])
    else:
        ev.append(["No evidence records"])
    style_sheet(ev, landscape=True)
    ev.auto_filter.ref = ev.dimensions
    ev.print_area = ev.dimensions

    # Make the summary and every data sheet printable on A4 without changing source data.
    for sheet in wb.worksheets:
        if sheet.title != "Evidence":
            sheet.print_area = sheet.dimensions
    wb.calculation.fullCalcOnLoad = True
    out = BytesIO()
    wb.save(out)
    return out.getvalue()

def make_pptx(rows, analysis, source, title="Vanguard-SIEM SOC Analytics Report") -> bytes:
    from pptx import Presentation
    from pptx.util import Inches, Pt

    ctx = report_context(rows, analysis, source); s = ctx["analytics"]
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[0]); slide.shapes.title.text = title
    slide.placeholders[1].text = f"{ctx['data_state']}\n{source}\nObserved: {ctx.get('first_seen') or 'N/A'} → {ctx.get('last_seen') or 'N/A'}\n{ctx['generated_at']}\nEvidence SHA-256: {ctx.get('evidence_sha256') or 'not supplied'}"
    slide = prs.slides.add_slide(prs.slide_layouts[5]); slide.shapes.title.text = "Executive analytics"
    tf = slide.shapes.add_textbox(Inches(1), Inches(1.2), Inches(11), Inches(5)).text_frame
    tf.text = "\n".join([
        f"Records: {s['records']:,}", f"Unique sources: {s['unique_sources']:,}", f"Unique targets: {s['unique_targets']:,}",
        f"Alert rate: {s['alert_rate_pct']}%", f"Critical rate: {s['critical_rate_pct']}%", f"Parse coverage: {ctx['parse_coverage']}%",
        f"Risk score: {ctx['risk_score']}", f"Raw alerts: {ctx['raw_alerts']:,}", f"Analyst finding groups: {ctx['finding_groups']:,}",
        f"Incidents: {ctx['incidents']:,}",
    ])
    for p in tf.paragraphs: p.font.size = Pt(22)

    slide = prs.slides.add_slide(prs.slide_layouts[5]); slide.shapes.title.text = "Severity distribution"
    tf = slide.shapes.add_textbox(Inches(1), Inches(1.3), Inches(11), Inches(5)).text_frame
    tf.text = "\n".join(f"{k}: {v:,}" for k, v in s["severity_counts"].items())

    slide = prs.slides.add_slide(prs.slide_layouts[5]); slide.shapes.title.text = "Top attack types"
    tf = slide.shapes.add_textbox(Inches(1), Inches(1.3), Inches(11), Inches(5)).text_frame
    tf.text = "\n".join(f"{k}: {v:,}" for k, v in s["top_attack_types"].items()) or "No detected attack types."

    trend = __import__("analytics").trend(rows)
    if not trend.empty:
        slide = prs.slides.add_slide(prs.slide_layouts[5]); slide.shapes.title.text = "Hourly trend"
        tf = slide.shapes.add_textbox(Inches(1), Inches(1.3), Inches(11), Inches(5)).text_frame
        tf.text = "\n".join(f"{row.period}: records={int(row.records):,}, alerts={int(row.alerts):,}, critical={int(row.critical):,}" for row in trend.tail(20).itertuples())
    out = BytesIO(); prs.save(out); return out.getvalue()


def make_csv(rows) -> bytes:
    df = pd.DataFrame(rows or [])
    return df.to_csv(index=False).encode("utf-8")


def make_html(rows, analysis, source, title="Vanguard-SIEM SOC Analytics Report") -> bytes:
    ctx = report_context(rows, analysis, source)
    s = ctx["analytics"]
    findings = __import__("analytics").findings_dataframe(analysis)
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#17212b}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #bbb;padding:6px;font-size:12px}}th{{background:#e8eef3}}@media print{{button{{display:none}}}}</style>
</head><body><button onclick="window.print()">Print report</button><h1>{title}</h1>
<p>Source: {source}<br>Generated: {ctx['generated_at']}<br>Evidence SHA-256: {ctx.get('evidence_sha256') or 'not supplied'}</p>
<h2>Executive analytics</h2><table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Records</td><td>{s['records']:,}</td></tr><tr><td>Unique sources</td><td>{s['unique_sources']:,}</td></tr>
<tr><td>Unique targets</td><td>{s['unique_targets']:,}</td></tr><tr><td>Alert rate</td><td>{s['alert_rate_pct']}%</td></tr>
<tr><td>Critical rate</td><td>{s['critical_rate_pct']}%</td></tr><tr><td>Risk score</td><td>{ctx['risk_score']}</td></tr>
<tr><td>Raw alerts</td><td>{ctx['raw_alerts']:,}</td></tr><tr><td>Analyst finding groups</td><td>{ctx['finding_groups']:,}</td></tr>
<tr><td>Incidents</td><td>{ctx['incidents']:,}</td></tr></table>
<h2>Severity</h2><table><tr><th>Severity</th><th>Count</th></tr>{''.join(f'<tr><td>{k}</td><td>{v:,}</td></tr>' for k,v in s['severity_counts'].items())}</table>
<h2>Top attack types</h2><table><tr><th>Attack type</th><th>Count</th></tr>{''.join(f'<tr><td>{str(k)}</td><td>{v:,}</td></tr>' for k,v in s['top_attack_types'].items())}</table>
</body></html>"""
    return html.encode("utf-8")


def export_bundle(rows, analysis, source, basename="vanguard_soc_report") -> dict[str, bytes]:
    return {
        "pdf": make_pdf(rows, analysis, source),
        "docx": make_docx(rows, analysis, source),
        "xlsx": make_xlsx(rows, analysis, source),
        "pptx": make_pptx(rows, analysis, source),
        "csv": make_csv(rows),
        "html": make_html(rows, analysis, source),
        "json": json.dumps(report_context(rows, analysis, source), indent=2).encode("utf-8"),
    }
