# SpecterMail XDR Security Review and Remediation Notes

## Architecture Diagram

```text
Browser
  | POST .eml/.txt or pasted content
  v
Flask routes
  | CSRF, upload validation, rate limit
  v
Parser layer
  | EML headers/body/attachments, TXT/manual text
  v
Detection pipeline
  | IOC extraction -> URL/domain analysis -> header auth analysis
  | language layers -> brand/TLD/shortener/reputation -> MITRE mapping
  v
Risk engine
  | threat score, confidence score, risk level (Informational-Low-Medium-High-Critical)
  v
Persistence and reports
  | SQLite ScanHistory, per-analysis JSON, PDF, IOC export, rotating logs
```

## Data Flow Summary

User input enters through `/` as uploaded email files or manual text. Uploaded files are renamed with a random analysis id, restricted to `.eml` and `.txt`, and stored under `instance/uploads`. EML files are parsed with Python's email policy parser. The analyzer normalizes URLs and IOCs, evaluates headers, language, domains, attachments, and MITRE evidence, then stores a ScanHistory row and per-analysis JSON under `instance/reports`.

## Security Boundary Map

| Boundary | Risk | Implemented Control |
| --- | --- | --- |
| Browser to Flask | CSRF, oversized request, repeated scans | CSRF token, max content length, rate limit |
| Upload to filesystem | traversal, executable upload, overwrite | extension allow-list, secure filename, per-analysis name, child-path check |
| Email to parser | malformed MIME, bad encoding, HTML noise | policy parser, error-tolerant decode, HTML text extraction |
| Analyzer to reports | report injection, shared latest overwrite | XML escaping in PDFs, per-analysis report files |
| App to DB | weak history, missing indexes | expanded ScanHistory with indexes and schema repair |
| Runtime to GitHub | secrets/runtime leakage | `.gitignore`, `.env.example`, env-driven config |

## Detection Pipeline Map

```text
Raw email
  -> normalized content
  -> URL normalization: hxxp, defanged dots, www, bare domains, IDN
  -> IOC extraction: IPv4, IPv6, emails, domains, MD5, SHA1, SHA256
  -> header analysis: SPF/DKIM/DMARC, Reply-To mismatch, Return-Path mismatch
  -> language layers: urgency, credential theft, financial, execution, CTA, brand
  -> domain layers: suspicious TLD, IP URL, punycode, impersonation, shortener
  -> MITRE mapping with tactic, confidence, evidence
  -> weighted scoring and risk level assignment
```

## Scoring Formula

Threat score is capped at 100 and combines weighted indicator categories. Scores map to risk levels (Informational, Low, Medium, High, Critical) without producing definitive email classifications. Confidence starts at 45 and increases with evidence volume.

## Bypass Scenarios Covered

| Attack | Previous Behavior | Fix |
| --- | --- | --- |
| `hxxps://evil[.]com` | missed | URL normalization |
| `www.evil.com/login` | missed | bare URL detection |
| `evil[.]com` | missed | defanged domain extraction |
| punycode brand domain | weak | punycode/homograph finding |
| invalid IP `999.999.999.999` | accepted as IOC | ipaddress validation |
| SHA1 mixed with SHA256 | one hash bucket | separated hash buckets |
| `spf=pass` in body | lowered header score | parse only headers/auth fields |
| Reply-To mismatch | generic only | domain mismatch evidence |
| report text with `<b>` tags | rendered markup | XML escaping in PDF |
| repeated scans flood | unlimited | rate limit |
| global latest report overwrite | shared artifact | per-analysis report ids |
| upload `../../x.eml` | path confusion risk | secure filename and child-path check |
| missing SECRET_KEY | hardcoded key | env-driven secret |
| debug server | always enabled | env controlled |
| GitHub upload of runtime files | likely | `.gitignore` added |

## Viva Questions

1. Why is parsing actual headers safer than searching the full email text for `spf=pass`?
2. What trust boundaries exist between the browser, parser, analyzer, reports, and database?
3. How does the system normalize defanged phishing URLs?
4. Why are IPv4 and IPv6 validated with `ipaddress` instead of regex alone?
5. What are the limits of keyword-based phishing detection?
6. How does the scoring model avoid unlimited score inflation?
7. Why is a confidence score different from a threat score?
8. How can ReportLab paragraph markup become a report injection issue?
9. What evidence supports each MITRE ATT&CK mapping?
10. Which controls are still demo-grade rather than enterprise-grade?

## Remaining Risks

The rate limiter is in-memory and should be replaced with Redis for multi-worker deployment. Domain age and reputation checks depend on network availability and should use timeouts/caching. Authentication analysis is still limited by what exists in the supplied email source. Production authentication and per-user authorization are not implemented because the app is currently a single-user analyzer.

## Project Grade

Before fixes: C+/B- as a portfolio demo with useful features but weak production controls.

After fixes: B+/A- for a final-year cybersecurity project, assuming tests pass and the viva clearly explains remaining limitations.
