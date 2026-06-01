#!/usr/bin/env python3
import argparse
import sys
from cryptography import x509

parser = argparse.ArgumentParser()
parser.add_argument('crl_file', nargs='?', default='crl.pem',
                    help='Path to CRL file (default: crl.pem)')
args = parser.parse_args()

if args.crl_file == '-':
    data = sys.stdin.buffer.read()
else:
    with open(args.crl_file, "rb") as f:
        data = f.read()

try:
    crl = x509.load_pem_x509_crl(data)
except ValueError:
    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        raise SystemExit("Failed to load CRL (neither PEM nor DER)")

print("Issuer:")
for rdn in crl.issuer.rdns:
    for attr in rdn:
        oid = attr.oid
        short = oid._name or oid.dotted_string
        print(f"{short}={attr.value}")
print(f"Last Update: {crl.last_update_utc}")
print(f"Next Update: {crl.next_update_utc}")
print("-" * 50)
for revoked in crl:
    serial_int = revoked.serial_number
    print(f"Serial: {serial_int}")

    hex_sn = format(serial_int, 'x')
    if len(hex_sn) % 2:
        hex_sn = '0' + hex_sn
    hex_sn = ':'.join(hex_sn[i:i+2] for i in range(0, len(hex_sn), 2))
    print(f"Serial (hex): {hex_sn}")

    print(f"Revocation Date: {revoked.revocation_date_utc}")

    print("CRL Entry Extensions:")
    if revoked.extensions:
        for ext in revoked.extensions:
            oid = ext.oid
            name = oid._name or oid.dotted_string
            critical = " (critical)" if ext.critical else ""
            print(f"  {name}{critical} [{oid.dotted_string}]: {ext.value}")
    else:
        print("  (none)")

    print("-" * 50)
