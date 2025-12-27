# acmecli.py

The `acmecli.py` tool is a lightweight client focused on ACMEv2 account management. It enables you to create, inspect, update, rekey, and deactivate your account. It also assists in configuring stateless challenges, specifically `http-01` and the experimental `dns-persist-01`.

You can use this tool to migrate between ACME clients or share a single ACME account across multiple clients or machines. The rationale behind ACME account reuse is detailed in the section **Stateless dns-persist-01**.

`acmecli.py` relies on upstream libraries to handle cryptography and network communication:
* [authlib/joserfc](https://github.com/authlib/joserfc) - [jose.authlib.org](https://jose.authlib.org/en/)
* [psf/requests](https://github.com/psf/requests) - [requests.readthedocs.io](https://requests.readthedocs.io/en/latest/)

This tool do not create any `key.pem` files automatically. To maintain a simple codebase and avoid security concerns related to key generation, you must create your private key yourself. Examples using `openssl` are provided below.

Currently, `acmecli.py` does not obtain certificates on its own. Adding this functionality is planned for a future release. Please note that as this project is in an early stage, the API is not frozen and may change without notice.

## Usage

```text
Usage:

acmecli.py [-a ACME_URL] -k key.(pem|json) account show [-d|-detail]
    Displays your account URI, status, and other details reported by the ACMEv2 server.

acmecli.py [-a ACME_URL] -k key.(pem|json) account create --help
    Creates a new ACMEv2 account. Before running this, you must generate a key file.

acmecli.py [-a ACME_URL] -k key.(pem|json) account update \
[mailto:user@example.com mailto:admin@example.net ... | clear]
    Updates your contact details. Contacts must be provided as a list.
    Prefix each contact with `mailto:`.
    WARNING: The magic word `clear` will remove all current contacts.
    Per RFC 8555, contacts are OPTIONAL, though some CAs (like pki.goog) require at
    least one contact.

acmecli.py [-a ACME_URL] -k key.(pem|json) account rekey new.(pem|json)
    Rekey your ACMEv2 account with a new private key.
    WARNING: This will change your key thumbprint but preserve your current account_uri.

acmecli.py [-a ACME_URL] -k key.(pem|json) account deactivate
    WARNING: This will permanently deactivate your account_uri AND invalidate the
    associated private key for this provider. You will not be able to reuse this
    private key on this ACMEv2 server again.

acmecli.py [-a ACME_URL] -k key.(pem|json) key thumbprint [-d|--detail]
    Prints your key thumbprint. This is used for stateless `http-01` configurations.
    See below.

acmecli.py [-a ACME_URL] -k key.(pem|json) key convert <pem|json>
    Converts keys between formats to facilitate migration between ACME clients.
    TIP: Most clients use `pem` format, but `certbot` uses the JSON Web Key (JWK) format.
```

Global parameters:
```text
ACME_URL must be one of:
* The full URL to your ACMEv2 directory, or
* A short alias: [letsencrypt | letsencrypt-staging | goog | goog-staging]

ACME_URL default value: letsencrypt.org production ACMEv2:
https://acme-v02.api.letsencrypt.org/directory
```

## Create account

This tool does not write files to disk. You must generate your private key manually before creating an account.

```bash
# RSA key (Standard compatibility)
openssl genrsa -out rsa.pem 3072

# ECDSA - NIST P-256 (Modern standard)
openssl ecparam -name prime256v1 -noout -genkey -out p256.pem

# ECDSA - NIST P-384
openssl ecparam -name secp384r1 -noout -genkey -out p384.pem

# ECDSA - NIST P-521
openssl ecparam -name secp521r1 -noout -genkey -out p521.pem

# Ed25519 - NOTE: Not currently supported by Let's Encrypt or Google Trust Services
openssl genpkey -algorithm ed25519 -out ed25519.pem
```

*Note: Most ACMEv2 servers widely support `RSA` and `P-256`.*

After generating the key, create your account on the ACMEv2 server:
```bash
acmecli.py -k yourkey.pem account create --contact mailto:admin@example.com
```

## Rekey account

If you need to change your private key (key rotation) without losing your account_uri, generate a `newkey.pem` using OpenSSL (see above). It does not need to be the same algorithm as the previous key. Then, rekey your account with a new key:

```bash
acmecli.py -k oldkey.pem account rekey newkey.pem
```

## Private key conversion

Different ACME clients require different private key formats. For example, `certbot` uses JSON Web Keys (JWK), while `lego`, `acme.sh`, and `uacme` typically use PEM encoded keys.

### Converting for Certbot
To migrate a PEM key to Certbot, convert it to JSON:

```bash
acmecli.py -k private.pem key convert json > private_key.json
```

*Note: Certbot expects this file at `/etc/letsencrypt/accounts/<server address>/<directory hash>/<account id>/private_key.json`. You may also need to manually construct the accompanying `meta.json` and `regr.json` metadata files required by Certbot. TODO: provide detailed instruction, on how to import privatekey into certbot reliably*

### Converting for Lego or uacme
To migrate a Certbot JWK key to a client that supports PEM:

```bash
acmecli.py -k private_key.json key convert pem > account.key
```

For `uacme`, place the resulting PEM file in `/etc/uacme.d/private/key.pem`.

* uacme supports hook scripts thay supports any challenge by the user himself.

For `lego`, place the resulting PEM file in `.lego/accounts/` - *TODO*

* Supports http-01 stateless by asking lego to write http challenge to webroot
  anywhere, it does not matter it writes a file, as long as your webservers are
  prepared upfront.

For `CertManager`, generate Kubernetes Secret and Issuer objects - *TODO*.

* does CertManager supports stateless http-01 without trying to
    alter Ingress?Investigate
* certainly CertManager does not support dns-persitent-01.

## Stateless http-01

Stateless verification allows many web servers to answer ACME `http-01`
challenges without writing temporary files (tokens) to the disk. This is ideal
for immutable infrastructure, containers, or multi-server clusters with Load
Balancer and auto-scalling group in front. Ensuring a file is reliably written
to all machines would be challenging, error prone and unreliable. It is also a
good option in Kubernetes, where your acme client does not have to alter / edit
your `Ingress` or `HTTPRoute` objects.

The `http-01` response is constructed as `token` + `.` + `key_thumbprint`. Since
the thumbprint represents your public portion of your account key, it is static.
The web server only needs to echo the token requested in the URL, followed by
your static thumbprint.

First, get your thumbprint:

```bash
acmecli.py -k privatekey.pem key thumbprint

Your public thumbprint: wppuytlzEm_i-rXLor8aqtTHJYZtk-J6qoh1WkIaEPA
```

### Nginx Example

```nginx

    location ~ ^/\.well-known/acme-challenge/([-_a-zA-Z0-9]+)$ {
      default_type text/plain;
      return 200 "$1.YOUR-THUMBPRINT-HERE";
    }
```

### Apache Example

```apache

<VirtualHost *:80>
    ...
    <LocationMatch "/.well-known/acme-challenge/(?<challenge>[-_a-zA-Z0-9]+)">
        RewriteEngine On
        RewriteRule "^([-_a-zA-Z0-9]+)$" "$1" [E=challenge:$1]
        ErrorDocument 200 "%{ENV:MATCH_CHALLENGE}.YOUR-THUMBPRINT-HERE"
        RewriteRule ^ - [L,R=200]
    </LocationMatch>
    ...
</VirtualHost>
```

### HAProxy Example

```haproxy
global
    setenv ACCOUNT_THUMBPRINT 'YOUR-THUMBPRINT-HERE'

frontend web
    mode  http
    bind :80
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\n" if { path_reg '^/.well-known/acme-challenge/[-_a-zA-Z0-9]+$' }
```

## Stateless dns-persist-01

The `dns-persist-01` challenge (defined in `draft-ietf-acme-dns-persist`) allows
for domain control validation via a **persistent** DNS TXT record. Unlike
`dns-01`, which requires updating DNS records for every challenge,
`dns-persist-01` allows you to set the record once and reuse it forever.

### Rationale for Account Reuse

Because the persistent DNS record must explicitly bind the domain to a specific
ACME account (via the `accounturi` parameter), re-using the same ACME account
across your infrastructure becomes highly beneficial. It avoids the need to
provision separate DNS records for every acme client instance requesting
certificates for the same domain or subdomain.

### Setup Instructions

1.  Retrieve your Account URI:

    Use `acmecli.py` to find the unique URI for your account. Your ACMEv2
    account is tied to the public portion of your private assymetric key:

    ```bash
    acmecli.py -k privatekey.pem account show

    Account URI: https://acme-staging-v02.api.letsencrypt.org/acme/acct/EXAMPLE12345
    ```

2.  Provision the DNS Record:

    Create a TXT record at `_validation-persist.<your-domain>`. The value must
    match the format defined in the draft, referencing the CA's issuer domain
    and your `accounturi`.

    *Example for "example.com" using Let's Encrypt:*

    ```text
    _validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/EXAMPLE12345"
    ```

3.  Issue Certificates

    Note: No ACMEv2 CA rolled out this challenge yet. It is planned for 2026.
    Also, no acme client supports this challenge (yet).

