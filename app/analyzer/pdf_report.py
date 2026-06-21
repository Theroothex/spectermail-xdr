from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfgen import canvas

from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape


def _safe(value, max_length=500):
    text = escape(str(value if value is not None else ""))
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    return [value]


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _limited(values, limit=80):
    return _as_list(values)[:limit]


def _tech_field(tech, field):
    if isinstance(tech, dict):
        return tech.get(field, "")
    if field == "name":
        return tech
    return ""


def _write_minimal_pdf(output_path, result, error):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf = canvas.Canvas(str(output_path))
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(72, 760, "SPECTERMAIL XDR EMAIL INTELLIGENCE REPORT")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(72, 730, "Report generated in minimal fallback mode.")
    pdf.drawString(72, 710, f"Status: {str(_as_dict(result).get('analysis_status', 'N/A'))[:80]}")
    pdf.drawString(72, 695, f"Risk Level: {str(_as_dict(result).get('risk_level', _as_dict(result).get('risk', 'N/A')))[:80]}")
    pdf.drawString(72, 680, f"Warning: {str(error)[:120]}")
    pdf.save()


def _build_fallback_pdf(output_path, result, error):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        doc = SimpleDocTemplate(str(output_path))
        styles = getSampleStyleSheet()
        doc.build([
            Paragraph("SPECTERMAIL XDR EMAIL INTELLIGENCE REPORT", styles["Title"]),
            Spacer(1, 20),
            Paragraph("Report generated in safe fallback mode.", styles["Normal"]),
            Paragraph(f"Analysis Status: {_safe(_as_dict(result).get('analysis_status', 'N/A'))}", styles["Normal"]),
            Paragraph(f"Risk Level: {_safe(_as_dict(result).get('risk_level', _as_dict(result).get('risk', 'N/A')))}", styles["Normal"]),
            Paragraph(f"Generation Warning: {_safe(error, 250)}", styles["Normal"]),
        ])
    except Exception:
        _write_minimal_pdf(output_path, result, error)


def generate_pdf_report(result, output_path):
    try:
        _generate_pdf_report(result, output_path)
    except Exception as exc:
        _build_fallback_pdf(output_path, result, exc)


def _generate_pdf_report(result, output_path):
    result = _as_dict(result)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(str(output_path))

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "SPECTERMAIL XDR EMAIL INTELLIGENCE REPORT",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Analysis Overview",
            styles["Heading1"]
        )
    )

    summary_table = Table(
        [
            ["Analysis Status", _safe(result.get("analysis_status", "Completed"))],
            ["Risk Level", _safe(result.get("risk_level", result.get("risk", "N/A")))],
            ["Confidence Score", f"{result.get('confidence', 'N/A')}%"],
            ["Indicators Identified", str(result.get("indicator_count", len(_as_list(result.get('observed_findings')))))],
        ],
        colWidths=[180, 220]
    )

    summary_table.setStyle(
        TableStyle([
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold")
        ])
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Observed Findings",
            styles["Heading1"]
        )
    )

    observed = _as_list(result.get("observed_findings", []))
    if observed:
        for item in observed:
            elements.append(
                Paragraph(f"- {_safe(item)}", styles["Normal"])
            )
    else:
        elements.append(
            Paragraph(
                "No significant indicators were observed during automated analysis.",
                styles["Normal"]
            )
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Threat Indicators",
            styles["Heading1"]
        )
    )

    breakdown = _as_dict(result.get("score_breakdown", {}))
    if breakdown:
        breakdown_data = [["Category", "Score"]]
        for category, score in breakdown.items():
            breakdown_data.append([_safe(category), str(score)])
        breakdown_table = Table(breakdown_data, colWidths=[220, 180])
        breakdown_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ])
        )
        elements.append(breakdown_table)
    else:
        elements.append(
            Paragraph("No threat indicator breakdown available.", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "IOC Intelligence",
            styles["Heading1"]
        )
    )

    ioc = _as_dict(result.get("ioc_findings", {}))
    domains = _as_list(ioc.get("domains"))
    emails = _as_list(ioc.get("emails"))
    urls = _as_list(result.get("urls"))

    elements.append(
        Paragraph(
            f"Domains: {len(domains)} | Emails: {len(emails)} | URLs: {len(urls)}",
            styles["Normal"]
        )
    )

    ioc_data = [["IOC Type", "Value"]]

    for email in _limited(emails):
        ioc_data.append([
            Paragraph("Email", styles["BodyText"]),
            Paragraph(_safe(email), styles["BodyText"])
        ])

    for domain in sorted(set(_limited(domains))):
        ioc_data.append([
            Paragraph("Domain", styles["BodyText"]),
            Paragraph(_safe(domain), styles["BodyText"])
        ])

    ips = ioc.get("ips")
    if not ips:
        ips = _as_list(ioc.get("ipv4")) + _as_list(ioc.get("ipv6"))

    for ip in _limited(ips):
        ioc_data.append([
            Paragraph("IP", styles["BodyText"]),
            Paragraph(_safe(ip), styles["BodyText"])
        ])

    hashes = (
        ioc.get("hashes")
        or _as_list(ioc.get("md5"))
        + _as_list(ioc.get("sha1"))
        + _as_list(ioc.get("sha256"))
    )
    for hash_value in _limited(hashes):
        ioc_data.append([
            Paragraph("Hash", styles["BodyText"]),
            Paragraph(_safe(hash_value), styles["BodyText"])
        ])

    if len(ioc_data) > 1:
        ioc_table = Table(ioc_data, colWidths=[120, 420])
        ioc_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ])
        )
        elements.append(ioc_table)
    else:
        elements.append(
            Paragraph("No IOCs detected", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Authentication Analysis",
            styles["Heading1"]
        )
    )

    headers = _as_list(result.get("header_findings", []))
    if headers:
        for item in headers:
            elements.append(
                Paragraph(f"- {_safe(item)}", styles["Normal"])
            )
    else:
        elements.append(
            Paragraph("No authentication observations recorded.", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Domain Intelligence",
            styles["Heading1"]
        )
    )

    findings = _as_list(result.get("domain_findings", []))
    if findings:
        for item in findings:
            elements.append(
                Paragraph(f"- {_safe(item)}", styles["Normal"])
            )
    else:
        elements.append(
            Paragraph("No domain intelligence observations recorded.", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "URL Intelligence",
            styles["Heading1"]
        )
    )

    url_findings = _as_list(result.get("url_reputation_findings", []))
    if url_findings:
        for item in url_findings:
            elements.append(
                Paragraph(f"- {_safe(item)}", styles["Normal"])
            )
    else:
        elements.append(
            Paragraph("No URL reputation observations recorded.", styles["Normal"])
        )

    detected_domains = set()
    for url in urls:
        try:
            domain = urlparse(url).netloc
            if domain:
                detected_domains.add(domain)
        except Exception:
            pass

    if detected_domains:
        elements.append(Paragraph("Detected URL Domains:", styles["Normal"]))
        for domain in sorted(detected_domains):
            elements.append(
                Paragraph(f"- {_safe(domain)}", styles["Normal"])
            )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "MITRE ATT&CK Mapping",
            styles["Heading1"]
        )
    )

    mitre = _as_list(result.get("mitre_techniques", []))
    if mitre:
        table_data = [["Technique ID", "Technique"]]
        for tech in mitre:
            table_data.append([
                _safe(_tech_field(tech, "id")),
                _safe(_tech_field(tech, "name"))
            ])
        mitre_table = Table(table_data, colWidths=[120, 250])
        mitre_table.setStyle(
            TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)
            ])
        )
        elements.append(mitre_table)
    else:
        elements.append(
            Paragraph("No MITRE techniques triggered", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Analyst Summary",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            _safe(result.get("analyst_summary", "Analysis summary unavailable.")),
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Recommendations",
            styles["Heading1"]
        )
    )

    recommendations = _as_list(result.get("recommendations", []))
    if recommendations:
        for item in recommendations:
            elements.append(
                Paragraph(f"- {_safe(item)}", styles["Normal"])
            )
    else:
        elements.append(
            Paragraph("No recommendations available.", styles["Normal"])
        )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Report Metadata",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Report ID: {result.get('analysis_id', 'N/A')}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            "Analyzer Version: SpecterMail XDR v2.0",
            styles["Normal"]
        )
    )

    try:
        doc.build(elements)
    except Exception as exc:
        _build_fallback_pdf(output_path, result, exc)
