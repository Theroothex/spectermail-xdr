import ipaddress
import re
from urllib.parse import urlparse

from app.analyzer.url_extractor import extract_urls


EMAIL_PATTERN = re.compile(
    r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_PATTERN = re.compile(
    r"(?i)(?<![a-f0-9:])(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}(?![a-f0-9:])"
)
DOMAIN_PATTERN = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b"
)
HASH_PATTERNS = {
    "md5": re.compile(r"(?i)\b[a-f0-9]{32}\b"),
    "sha1": re.compile(r"(?i)\b[a-f0-9]{40}\b"),
    "sha256": re.compile(r"(?i)\b[a-f0-9]{64}\b"),
}


def _dedupe(values):
    return list(dict.fromkeys(values))


def _valid_ip(value, version):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if address.version != version:
        return ""
    return str(address)


def extract_iocs(content):

    findings = {

        "ips": [],
        "ipv4": [],
        "ipv6": [],
        "domains": [],
        "emails": [],
        "hashes": [],
        "md5": [],
        "sha1": [],
        "sha256": [],
        "urls": []

    }

    normalized_content = (
        (content or "")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
    )

    ipv4 = [
        ip
        for ip in (
            _valid_ip(match.group(0), 4)
            for match in IPV4_PATTERN.finditer(normalized_content)
        )
        if ip
    ]
    ipv6 = [
        ip
        for ip in (
            _valid_ip(match.group(0), 6)
            for match in IPV6_PATTERN.finditer(normalized_content)
        )
        if ip
    ]
    findings["ipv4"] = _dedupe(ipv4)
    findings["ipv6"] = _dedupe(ipv6)
    findings["ips"] = findings["ipv4"] + findings["ipv6"]

    emails = [
        match.group(0).lower()
        for match in EMAIL_PATTERN.finditer(normalized_content)
    ]
    findings["emails"] = _dedupe(emails)

    urls = extract_urls(content or "")
    findings["urls"] = urls

    domains = []
    email_domains = {email.rsplit("@", 1)[1] for email in findings["emails"]}
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.append(parsed.hostname.lower())

    for match in DOMAIN_PATTERN.finditer(normalized_content):
        domain = match.group(0).lower().rstrip(".")
        if domain not in email_domains:
            try:
                domain = domain.encode("idna").decode("ascii")
            except UnicodeError:
                continue
            domains.append(domain)

    findings["domains"] = _dedupe(domains)

    for name, pattern in HASH_PATTERNS.items():
        values = [
            match.group(0).lower()
            for match in pattern.finditer(normalized_content)
        ]
        findings[name] = _dedupe(values)

    findings["hashes"] = _dedupe(
        findings["md5"] + findings["sha1"] + findings["sha256"]
    )

    return findings
