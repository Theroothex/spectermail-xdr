from urllib.parse import urlparse


TRUSTED_ORG_DOMAINS = {
    "amazon.com",
    "amazon.co.uk",
    "amazon.in",
    "amazonpay.in",
    "apple.com",
    "c.gle",
    "flipkart.com",
    "g.co",
    "github.net",
    "github.com",
    "githubassets.com",
    "google.com",
    "googlemail.com",
    "googleusercontent.com",
    "gmail.com",
    "goo.gle",
    "icloud.com",
    "linkedin.com",
    "licdn.com",
    "live.com",
    "microsoft.com",
    "microsoftonline.com",
    "netflix.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "paypal.com",
    "paypalobjects.com",
    "windows.net",
    "azure.com",
    "youtube.com",
}

BRAND_ASSOCIATED_DOMAINS = {
    "amazon": {
        "amazon.com",
        "amazon.co.uk",
        "amazon.in",
        "amazonpay.in",
        "amazonses.com",
    },
    "apple": {"apple.com", "icloud.com"},
    "flipkart": {"flipkart.com"},
    "github": {
        "github.com",
        "github.net",
        "githubassets.com",
        "githubusercontent.com",
    },
    "google": {
        "google.com",
        "googlemail.com",
        "googleusercontent.com",
        "gmail.com",
        "g.co",
        "goo.gle",
        "c.gle",
        "youtube.com",
    },
    "linkedin": {"linkedin.com", "licdn.com"},
    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "live.com",
        "windows.net",
        "azure.com",
    },
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com", "paypalobjects.com"},
}


MULTI_PART_SUFFIXES = {
    "co.in",
    "com.au",
    "co.uk",
    "com.br",
    "co.jp",
    "co.nz",
}


def normalize_domain(domain):
    value = (domain or "").strip().lower().rstrip(".")
    if value.startswith("www."):
        value = value[4:]
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def domain_from_url(url):
    parsed = urlparse(url or "")
    return normalize_domain(parsed.hostname or parsed.netloc)


def organizational_domain(domain):
    normalized = normalize_domain(domain)
    labels = normalized.split(".")
    if len(labels) <= 2:
        return normalized
    suffix = ".".join(labels[-2:])
    if suffix in MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def same_organization(first, second):
    first_org = organizational_domain(first)
    second_org = organizational_domain(second)
    return bool(first_org and second_org and first_org == second_org)


def is_subdomain_of(domain, parent):
    normalized = normalize_domain(domain)
    parent = normalize_domain(parent)
    return bool(
        normalized
        and parent
        and (normalized == parent or normalized.endswith("." + parent))
    )


def is_trusted_domain(domain):
    return any(
        is_subdomain_of(domain, trusted)
        for trusted in TRUSTED_ORG_DOMAINS
    )


def is_brand_associated_domain(brand, domain):
    return any(
        is_subdomain_of(domain, associated)
        for associated in BRAND_ASSOCIATED_DOMAINS.get(brand, set())
    )
