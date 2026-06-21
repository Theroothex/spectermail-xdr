# SpecterMail XDR - Email Intelligence & Analysis Platform

SpecterMail XDR is a Flask-based email intelligence platform for parsing email content, extracting IOCs, correlating indicators, mapping evidence to MITRE ATT&CK, and producing analyst-friendly intelligence reports.

## Key Capabilities

- EML, TXT, and pasted-content analysis
- URL normalization for `http`, `https`, `hxxp`, `hxxps`, `www`, bare domains, and defanged domains
- IOC extraction for domains, emails, IPv4, IPv6, MD5, SHA1, and SHA256
- Header analysis for SPF, DKIM, DMARC, Reply-To mismatch, Return-Path mismatch, and suspicious sender TLDs
- Multi-layer indicator detection for urgency, credential theft, brand impersonation, suspicious domains, suspicious TLDs, shorteners, IOC density, and authentication failures
- Risk level, confidence score, observed findings, MITRE evidence, PDF report, IOC export, dashboard, and scan history

## Setup

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python run.py
```

Set a strong `SECRET_KEY` in `.env` before using the app outside local development.

## Security Controls

- Environment-driven secret/config management
- CSRF token on the analysis form
- Request size limit and basic rate limiting
- Upload extension allow-list and path traversal protection
- Runtime files stored under `instance/`
- Secure response headers
- Per-analysis report files to prevent latest-report overwrites
- Rotating application, security, audit, and analysis logs
- PDF output escaping to prevent ReportLab markup injection

## Scoring

The internal threat score is capped at 100 and combines authentication failures, suspicious domains, brand impersonation, credential-theft language, urgency language, IOC density, suspicious TLDs, shorteners, URL reputation, domain age, URL count, and keyword indicators. Scores map to risk levels (Informational, Low, Medium, High, Critical) without producing definitive email classifications.

## Reporting Model

Reports present analysis status, risk level, confidence score, indicator count, observed findings, IOC intelligence, authentication analysis, domain intelligence, URL intelligence, MITRE ATT&CK mapping, evidence-based analyst summaries, and actionable recommendations.

## testing

```powershell
pytest
```

The current regression tests cover URL normalization, IOC validation, header spoofing resistance, and score capping.

## Security Review

See `SECURITY_REVIEW.md` for architecture diagrams, trust boundaries, detection pipeline mapping, bypass scenarios, scoring formulas, viva questions, and remaining risks.
