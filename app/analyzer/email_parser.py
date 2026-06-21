from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path


class _HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        if data.strip():
            self.parts.append(data.strip())

    def handle_starttag(self, tag, attrs):
        if tag not in {"a", "area"}:
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.parts.append(value.strip())

    def text(self):
        return " ".join(self.parts)


def _html_to_text(value):
    parser = _HTMLTextExtractor()
    parser.feed(value or "")
    return parser.text()


def _safe_part_content(part):
    try:
        value = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        value = payload.decode(charset, errors="replace")

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def parse_eml(file_path):

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = str(msg.get("subject", ""))
    sender = str(msg.get("from", ""))
    recipient = str(msg.get("to", ""))
    sender_email = parseaddr(sender)[1].lower()
    text_parts = []
    html_parts = []
    attachments = []

    if msg.is_multipart():

        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            filename = part.get_filename()

            if filename or disposition == "attachment":
                attachments.append({
                    "filename": filename or "unnamed",
                    "content_type": content_type,
                    "size": len(part.get_payload(decode=True) or b""),
                })
                continue

            if content_type == "text/plain":
                text_parts.append(_safe_part_content(part))

            elif content_type == "text/html":
                html_parts.append(_html_to_text(_safe_part_content(part)))

    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            html_parts.append(_html_to_text(_safe_part_content(msg)))
        else:
            text_parts.append(_safe_part_content(msg))

    body = "\n".join(part for part in text_parts + html_parts if part)
    headers = "\n".join(f"{key}: {value}" for key, value in msg.items())
    raw_content = "\n\n".join(part for part in (headers, body) if part)

    return {
        "subject": subject,
        "sender": sender,
        "sender_email": sender_email,
        "recipient": recipient,
        "body": body,
        "headers": headers,
        "raw": raw_content,
        "attachments": attachments,
        "source_filename": Path(file_path).name,
    }
