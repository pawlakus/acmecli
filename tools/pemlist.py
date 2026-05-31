#!/usr/bin/env python3
import argparse
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def load_certificates(pem_data: bytes):
    pattern = re.compile(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
    for match in pattern.findall(pem_data):
        yield x509.load_pem_x509_certificate(match, default_backend())

def format_alt_names(ext):
    dns = ext.value.get_values_for_type(x509.DNSName)
    ips = ext.value.get_values_for_type(x509.IPAddress)
    lines = []
    if dns:
        lines.append("    DNS: " + ", ".join(dns))
    if ips:
        lines.append("    IP: " + ", ".join(str(ip) for ip in ips))
    return lines or ["    (none)"]

def _format_sn(serial_int: int):
    hex_sn = format(serial_int, 'x')
    if len(hex_sn) % 2:
        hex_sn = '0' + hex_sn
    return ':'.join(hex_sn[i:i+2] for i in range(0, len(hex_sn), 2))

def _get_validity_attribute(cert, attr):
    utc_attr = f"{attr}_utc"
    if hasattr(cert, utc_attr):
        return getattr(cert, utc_attr)
    return getattr(cert, attr)

def describe_certificate(cert: x509.Certificate) -> str:
    parts = [
        f"Subject   : {cert.subject.rfc4514_string()}",
        f"Issuer    : {cert.issuer.rfc4514_string()}",
        f"Not Before: {_get_validity_attribute(cert, 'not_valid_before').isoformat()}",
        f"Not After : {_get_validity_attribute(cert, 'not_valid_after').isoformat()}",
        f"Serial    : {_format_sn(cert.serial_number)}",
    ]

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        ca = "true" if bc.ca else "false"
        pathlen = f", pathlen={bc.path_length}" if bc.path_length is not None else ""
        parts.append(f"CA        : {ca}{pathlen}")
    except x509.ExtensionNotFound:
        parts.append("CA        : (absent)")

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        parts.append("Alt Names :")
        parts.extend(format_alt_names(san))
    except x509.ExtensionNotFound:
        parts.append("Alt Names : (none)")

    return "\n".join(parts)

def main():
    parser = argparse.ArgumentParser(description="Print readable info from PEM certificates.")
    parser.add_argument("pem_file", help="PEM file containing one or more certificates.")
    args = parser.parse_args()

    with open(args.pem_file, "rb") as f:
        data = f.read()

    certs = list(load_certificates(data))
    if not certs:
        print("No certificates found.")
        return

    separator = "=" * 72
    for index, cert in enumerate(certs, start=1):
        print(separator)
        print(f"Certificate #{index}")
        print(separator)
        print(describe_certificate(cert))
        print()

if __name__ == "__main__":
    main()
