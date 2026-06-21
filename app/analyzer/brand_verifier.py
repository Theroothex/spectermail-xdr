from app.analyzer.domain_utils import domain_from_url, is_brand_associated_domain


BRANDS = (
    "amazon",
    "apple",
    "flipkart",
    "github",
    "google",
    "linkedin",
    "microsoft",
    "netflix",
    "paypal",
)


def verify_brand(urls):
    findings = []
    suspicious_score = 0

    for url in urls:
        domain = domain_from_url(url)
        if not domain:
            continue

        for brand in BRANDS:
            if brand not in domain:
                continue
            if is_brand_associated_domain(brand, domain):
                continue

            finding = f"Brand Impersonation Detected ({brand} in {domain})"
            if finding not in findings:
                findings.append(finding)
                suspicious_score += 25

    return findings, suspicious_score
