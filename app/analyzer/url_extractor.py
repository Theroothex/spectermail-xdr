import re
from urllib.parse import urlsplit, urlunsplit


TRAILING_PUNCTUATION = ".,;:!?)>]}'\""
URL_PATTERN = re.compile(
    r"(?ix)\b("
    r"(?:hxxps?|https?)://[^\s<>'\"]+|"
    r"www\.[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:/[^\s<>'\"]*)?"
    r")"
)


def _dedupe(values):
    return list(dict.fromkeys(values))


def normalize_url(value):
    candidate = (value or "").strip().strip(TRAILING_PUNCTUATION)
    candidate = (
        candidate.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
    )
    candidate = re.sub(r"(?i)^hxxps://", "https://", candidate)
    candidate = re.sub(r"(?i)^hxxp://", "http://", candidate)

    if candidate.startswith("www."):
        candidate = "http://" + candidate

    if "://" not in candidate:
        candidate = "http://" + candidate

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return ""

    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        return ""

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""

    try:
        port_value = parsed.port
    except ValueError:
        return ""
    port = f":{port_value}" if port_value else ""
    netloc = host + port
    if parsed.username:
        return ""

    path = parsed.path or ""
    return urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))


def extract_urls(content):
    matches = [match.group(1) for match in URL_PATTERN.finditer(content or "")]
    normalized = [
        normalized
        for normalized in (normalize_url(match) for match in matches)
        if normalized
    ]
    return _dedupe(normalized)
