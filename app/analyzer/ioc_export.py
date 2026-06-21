from pathlib import Path


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _write_values(file, values):
    values = _as_list(values)
    if values:
        for value in values:
            file.write(f"- {value}\n")
    else:
        file.write("None Detected\n")


def generate_ioc_report(iocs, output_path):
    iocs = _as_dict(iocs)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "IOC EXTRACTION REPORT\n"
        )

        file.write(
            "=" * 40 + "\n\n"
        )

        # IPs
        file.write("IP ADDRESSES\n")

        ips = iocs.get("ips")
        if not ips:
            ips = _as_list(iocs.get("ipv4")) + _as_list(iocs.get("ipv6"))
        _write_values(file, ips)

        file.write("\n")

        # Emails
        file.write("EMAIL ADDRESSES\n")

        _write_values(file, iocs.get("emails"))

        file.write("\n")

        # Domains
        file.write("DOMAINS\n")

        _write_values(file, iocs.get("domains"))

        file.write("\n")

        # Hashes
        file.write("HASHES\n")

        hashes = (
            iocs.get("hashes")
            or _as_list(iocs.get("md5"))
            + _as_list(iocs.get("sha1"))
            + _as_list(iocs.get("sha256"))
        )
        _write_values(file, hashes)
