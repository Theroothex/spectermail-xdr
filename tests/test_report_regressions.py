from app.analyzer.pdf_report import generate_pdf_report


def test_pdf_generation_handles_mixed_legacy_report_shapes(tmp_path):
    output_path = tmp_path / "intelligence_report.pdf"
    result = {
        "analysis_id": "legacy",
        "analysis_status": "Completed",
        "risk": "LOW",
        "risk_level": "Low",
        "score": 12,
        "confidence": 90,
        "indicator_count": 2,
        "observed_findings": [
            "SPF Passed",
            "External URL Present",
        ],
        "threat_summary": "single string summary",
        "keywords": None,
        "urls": ["https://www.flipkart.com/order"],
        "domain_findings": ["Trusted Domain Detected (flipkart.com)"],
        "mitre_techniques": [
            "Legacy string technique",
            {"id": "T1566", "name": "Phishing", "evidence": ["x"]},
        ],
        "header_findings": ["SPF Authentication Passed"],
        "attachment_findings": None,
        "ioc_findings": "legacy invalid ioc object",
        "recommendations": None,
        "analyst_summary": (
            "No significant suspicious indicators were observed during "
            "automated analysis."
        ),
    }

    generate_pdf_report(result, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0
