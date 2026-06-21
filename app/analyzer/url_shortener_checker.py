from urllib.parse import urlparse


SHORTENER_DOMAINS = {

    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "rb.gy",
    "t.co",
    "c.gle",
    "goo.gl",
    "ow.ly",
    "is.gd"

}


def check_url_shorteners(urls):

    findings = []

    detected_domains = set()

    for url in urls:

        domain = (
            urlparse(url)
            .netloc
            .lower()
        )

        domain = domain.replace(
            "www.",
            ""
        )

        if domain in SHORTENER_DOMAINS:

            detected_domains.add(
                domain
            )

    # Add findings only once
    for domain in sorted(
        detected_domains
    ):

        findings.append(
            f"URL Shortener Detected ({domain})"
        )

    # Risk scoring
    score = 0

    if detected_domains:

        # Low-confidence signal only; many legitimate notifications use redirects.
        score = 2

    return findings, score
