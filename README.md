# acmecli.py

The `acmecli.py` tool is a lightweight client focused on ACMEv2 account
management. It allows you to create, inspect, update, rekey, and deactivate your
ACMEv2 account. It also assists in configuring stateless challenges,
specifically `http-01` and the experimental `dns-persist-01`.

You can use this tool to migrate between ACME clients or share a single ACME
account across multiple clients or machines. The rationale behind ACME account
reuse is detailed in the section **Stateless dns-persist-01**.

`acmecli.py` relies on upstream libraries to handle cryptography and network
communication:
* [authlib/joserfc](https://github.com/authlib/joserfc) -
  [jose.authlib.org](https://jose.authlib.org/en/)
* [psf/requests](https://github.com/psf/requests) -
  [requests.readthedocs.io](https://requests.readthedocs.io/en/latest/)

This tool do not create any `key.pem` files automatically. To maintain a simple
codebase and avoid security concerns related to key generation, you must create
your private key yourself. Examples using `openssl` are provided below.

Currently, `acmecli.py` does not obtain certificates on its own. Adding this
functionality is planned for a future release. Please note that as this project
is in an early stage, the API is not frozen and may change without notice.

## Why?

* Easily obtain `thumbprint` for your current ACMEv2 account and setup stateless
  `http-01` challenge.

* Easily obtain `account_uri` and use it in your `CAA` records:
  ```
  example.org.    600 IN    CAA 0 issue "letsencrypt.org;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456"
  ```

* To use `account_uri` for future `dns-persist-01` challenge,
  [see this announcement from Let's Encrypt](https://letsencrypt.org/2025/12/02/from-90-to-45#making-automation-easier-with-a-new-dns-challenge-type)

* To create, convert, re-use, deactivate and merge many ACMEv2 accounts under one
  `privatekey` and `account_uri` to minimize DNS `CAA` records count.

* To help you create appropriate DNS records, like `CAA` for all methods, and other records for
  various challenge methods: `dns-persist-01`, `dns-account-01`.

* This ACMEv2 client **DOES NOT issue** any certificates (yet).



## Usage:

```text
usage: acmecli.py [-h] [-v] [-a ACME_URL] -k FILE {account,dns,key} ...

positional arguments:
  {account,dns,key}
    account             Account operations
    dns                 DNS helper functions
    key                 Key operations

options:
  -h, --help            show this help message and exit
  -v, --verbose
  -a ACME_URL, --acme-url ACME_URL
  -k FILE, --key FILE   Path to the private key file

Epilog:
[-a | --acme-url] can be either a full https://.../directory, or a keyword:
    letsencrypt | letsencrypt-staging | goog | goog-staging
[-k | --key ] is required for every action of this tool. Point it to the account private key.
    Private key format supported: JSON Web Token or PEM format.

Connects to ACMEv2 URL, online operations:
acmecli.py -k ... account show [-d]       obtain your account_uri and other details.
acmecli.py -k ... account create          create new ACMEv2 account_uri with account key provided upfront.
acmecli.py -k ... account deactivate      deactivates your public key and account_uri. Irreversible!
acmecli.py -k ... account update          updates your contact[] list for your account_uri.
acmecli.py -k ... account rekey new.pem   re-key your account_uri with new account private key.
acmecli.py -k ... dns records             provide various DNS records for various challenge methods. You have
                                          to add DNS records to your zone yourself.

Account private key - offline operation:
acmecli.py -k ... key thumbprint [-d]     calculates your account public key thumbprint. for stateless http-01.
acmecli.py -k ... key convert             converts your account private key to a different format.
```

### Account key usage

```text
$ acmecli.py key -h
usage: acmecli.py key [-h] {thumbprint,convert} ...

positional arguments:
  {thumbprint,convert}
    thumbprint          Print key thumbprint
    convert             Convert key format. Writes to stdout, even binary formats!

options:
  -h, --help            show this help message and exit

Account private key - offline operation:
acmecli.py -k ... key thumbprint [-d]            calculates your account public key thumbprint. for stateless http-01.
acmecli.py -k ... key convert                    converts your account private key to a different format.

Account private key conversions:
acmecli.py -k ... key convert pem   > out.pem    convert to PEM format. Depending on cryptography version, either PKCS#1 or PKCS#8.
acmecli.py -k ... key convert pkcs1 > out.pem    convert to PEM encoded as PKCS1. (BEGIN RSA PRIVATE KEY | BEGIN EC PRIVATE KEY).
acmecli.py -k ... key convert pkcs8 > out.pem    convert to PEM encoded as PKCS8. (BEGIN PRIVATE KEY).
acmecli.py -k ... key convert der1  > out.der    convert to DER encoded as PKCS1. (Binary).
acmecli.py -k ... key convert der8  > out.der    convert to DER encoded as PKCS8. (Binary).
acmecli.py -k ... key convert json  > out.json   convert to JSON Web Key format. (JSON, for certbot).
```

### Account management

```text
$ ./acmecli.py account -h
usage: acmecli.py account [-h] {show,update,create,rekey,deactivate} ...

positional arguments:
  {show,update,create,rekey,deactivate}
    show                Show account details
    update              Update account contacts
    create              Create new account
    rekey               Change account keys (Rollover)
    deactivate          Deactivate account

options:
  -h, --help            show this help message and exit

acmecli.py -k ... account create \
--eab-kid EAB_KEYID
--eab-hmac-key EAB_HMAC_KEY_BASE64
--eab-alg {HS256,HS384,HS512}
--agree-tos

    Creates a new ACMEv2 account. Before running this, you must generate a key file:

    # RSA key (Standard compatibility)
    openssl genrsa -out rsa.pem 3072

    # ECDSA - NIST P-256 (Modern standard)
    openssl ecparam -name prime256v1 -noout -genkey -out p256.pem

    # ECDSA - NIST P-384
    openssl ecparam -name secp384r1 -noout -genkey -out p384.pem

    # ECDSA - NIST P-521
    openssl ecparam -name secp521r1 -noout -genkey -out p521.pem

acmecli.py -k ... account update \
[mailto:user@example.com mailto:admin@example.net ... | clear]

    Updates your contact details. Contacts must be provided as a list.
    Prefix each contact with `mailto:`.
    WARNING: The magic word `clear` will remove all current contacts.
    Per RFC 8555, contacts are OPTIONAL, though some CAs (like pki.goog) require at
    least one contact.

acmecli.py -k ... account rekey newkey.pem
    Rekey your ACMEv2 account with a new private key.
    WARNING: This will change your key thumbprint but preserve your current account_uri.

acmecli.py -k ... account deactivate
    WARNING: This will permanently deactivate your account_uri AND invalidate the
    associated private key for this provider. You will not be able to reuse this
    private key on this ACMEv2 server again.
```

## ACMEv2 Account Basics

1. **Key generation** - The user creates an **asymmetric private key** (RSA, EC).

2. **Key parts** - The assymetric key contains a **private** component (kept
   secret) and a **public** component (mathematically derived from the private
   part). For simplicity, we will call them `private key` and `public key`,
   respectivelly, however: on disk you store only the `private key`.

3. **Secrets** - Your **private** key component - `private key` - is used to
   sign all communication, but is never revealed to anybody, including ACMEv2
   server. You only pass the **public** component - `public key`. Nobody except
   you knows your private key. ACMEv2 server use your `public key` to validate
   your signatures as a proof you actually do have your `private key`.

3. **Account URI** - When you create new ACMEv2 account, the ACME server assigns
   an `account_uri` that is bound to the *public* part of your key - `public key`.

4. **Thumbprint** - A hash of the `public key` (per RFC 7638). It is **not
   secret**; anyone in the world may know it without compromising the account.
   It is computed from a **public** component of your asymmetric key.

5. **Re-keying** - You can replace your assymetric `private key` to the same
   ACMEv2 `account URI` but your `thumbprint` will change as a result. For this
   operation **you need both your old and new** `private key` to cross-sign this
   action by **both keys**. Once completed, ACME server updates the account to
   point to the new `public key` while preserving the same `account URI`.

6. **Private key lost** - Once you lost your `private key`, you can not **rekey** anymore.
   Your `account_uri` is lost forever, you also can not **deactivate** it either.
   Create a new `assymetric private key` and a new ACMEv2 account.

7. This `acmecli.py` uses your **assymetric** `private key` for all operations but
   the **private** component never leaves your machine. On disk, you only store
   a `PEM` file that is the `private key`, or a Certbot `JSON` file that contains both
   **private and public** component pre-computed. **Never share or publish your**
   `key.pem` or `key.json` **!!!**

## Create account

This tool does not write files to disk. You must generate your private key
manually before creating an account. Use `openssl` version `3.x` or any
derivative, like `libressl`, `aws-lc`, etc.

```bash
# RSA key (Standard compatibility)
openssl genrsa -out rsa.pem 3072

# ECDSA - NIST P-256 (Modern standard)
openssl ecparam -name prime256v1 -noout -genkey -out p256.pem

# ECDSA - NIST P-384
openssl ecparam -name secp384r1 -noout -genkey -out p384.pem

# ECDSA - NIST P-521
openssl ecparam -name secp521r1 -noout -genkey -out p521.pem

# Ed25519 - deprecated:
openssl genpkey -algorithm ed25519 -out ed25519.pem
```

*Note: Most ACMEv2 servers widely support `RSA` and `P-256`. Others may not work.*

After generating the key, here is an example to create your new ACMEv2 account
with two contacts:

```bash
acmecli.py -k yourkey.pem account create mailto:admin@example.com mailto:noc@example.net
```
*Note: prefix your contact mail with **mailto:** - this is part of the RFC 8555 specification.*

## Re-key your ACMEv2 account

If you need to change your `private key` (key rotation) without losing your
`account_uri`, generate a `newkey.pem` using `openssl` (see above). It does not
need to be the same algorithm as the previous private key. You can swap `RSA`
for `EC` or vice versa.

Then, **rekey** your account with a `new private key`:

```bash
acmecli.py -k oldkey.pem account rekey newkey.pem
```

For this operation, `acmecli.py` needs to prove you have both your **old and
new** private keys.

## Private key conversion

Different ACME clients require different `private key` formats. For example,
`certbot` uses **JSON Web Keys** (JWK), while `lego`, `acme.sh`, and `uacme` and
most others use `PEM` encoded private keys.

### Converting for Certbot
To migrate a `PEM` `private key` to Certbot `JWK`, convert it to `JSON`:

```bash
acmecli.py -k private.pem key convert json > private_key.json
```

*Note: Certbot expects this file at `/etc/letsencrypt/accounts/<server
address>/<directory hash>/<account id>/private_key.json`. You may also need to
manually construct the accompanying `meta.json` and `regr.json` metadata files
required by Certbot. TODO: provide detailed instruction, on how to import
privatekey into certbot reliably*

### Converting for Lego or uacme
To migrate a Certbot `JWK` `private key` to a client that supports `PEM`:

```bash
acmecli.py -k private_key.json key convert pem > account.key
```

For `uacme`, place the resulting `PEM` file in `/etc/uacme.d/private/key.pem`.

* `uacme` supports hook scripts thay supports any challenge by the user himself.

For `lego`, place the resulting PEM file in `.lego/accounts/` - *TODO*

* Supports `http-01 stateless` by asking lego to write http challenge anywhere,
  it does not matter where it writes a file, as long as your webservers are
  prepared upfront.

For `CertManager`, generate `Kubernetes` `Secret` and `Issuer` objects

* TODO: *Provide a detailed way to import ACMEv2 account to CertManager*.

* does `CertManager` supports `stateless http-01` without trying to
    alter Ingress? *TODO: Investigate*
* certainly `CertManager` does not support `dns-persitent-01`.

# Stateless http-01

Stateless verification lets any web server answer the ACME `http‑01` challenge
for your ACME account without writing a temporary file. The response is simply:

```
<token>.<key‑thumbprint>
```

where the `thumbprint` is derived from the **public** part of your account key
and never changes, and `token` is part of the **GET** `URI` request send by ACMEv2
to your web server(s).

**Thumbprint** is not a secret and revealing it to the whole world does not
compromise your `private key` or your ACMEv2 account.

## When to use

* ACMEv2 client runs on a different machine than the HTTP server

* ACMEv2 client runs by different Team than who is managing the HTTP server

* ACMEv2 client does not have write permissions to
  `/.well-known/acme-challenge/` or syncing it reliably across different servers
  would be unreliable and error prone.

* traffic is load‑balanced across many servers – no need to sync files

* Kubernetes / OpenShift – no Ingress/HTTPRoute modifications required

* geo‑distributed CDN – every edge node can answer the challenge on the fly.


## Cross site scripting vulnerability risk

* Incorrect implementation can introduce XSS. The examples below enforce a
  strict regexp for base64url alphabet that do not allow HTML tags.

* All examples [are copied from acme.sh wiki](https://github.com/acmesh-official/acme.sh/wiki/Stateless-Mode).

* See [RFC 8555, section 8.3](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3):


   Note that because the token appears both in the request sent by the
   ACME server and in the key authorization in the response, it is
   possible to build clients that copy the token from request to
   response.  Clients should avoid this behavior because it can lead to
   cross-site scripting vulnerabilities; instead, clients should be
   explicitly configured on a per-challenge basis.
   
   **A client that does copy tokens from requests to responses MUST validate
   that the token in the request matches the token syntax above (e.g., that it
   includes only characters from the base64url alphabet).**

* That is why every example bellow uses `([-_a-zA-Z0-9]+)` as their regexp.

## Configure

First, get your `thumbprint` for your `private key`:

```bash
acmecli.py -k privatekey.pem key thumbprint

Your public thumbprint: wppuytlzEm_i-rXLor8aqtTHJYZtk-J6qoh1WkIaEPA
```

## Nginx Example

```nginx
server {
    listen 80 default;
    location ~ ^/\.well-known/acme-challenge/([-_a-zA-Z0-9]+)$ {
      default_type text/plain;
      return 200 "$1.YOUR-THUMBPRINT-HERE";
    }
}
```

## Apache Example

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

## HAProxy Example

```haproxy
global
    setenv ACCOUNT_THUMBPRINT 'YOUR-THUMBPRINT-HERE'

frontend web
    mode  http
    bind :80
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\n" if { path_reg '^/.well-known/acme-challenge/[-_a-zA-Z0-9]+$' }
```

## Manually test the challenge

If you see the following output on your web server **example.com**, you are
ready to pass the `http-01` challenge **statelessly** with your ACME account.

```bash
curl -s http://example.com/.well-known/acme-challenge/Anything-you-type-here-must-return

Anything-you-type-here-must-return.wppuytlzEm_i-rXLor8aqtTHJYZtk-J6qoh1WkIaEPA
```

It does not matter what value you put under
`/.well-known/acme-challenge/<token>`; you webserver must return it on‑the‑fly
in the format `<token>.<key-thumbprint>`. The ACMEv2 `CA` will request this
*FQDN* and expect a correctly formatted response, which your web server
generates on the fly.


# Stateless dns-persist-01

The `dns-persist-01` challenge (defined in `draft-ietf-acme-dns-persist`) allows
for domain control validation via a **persistent** DNS `TXT` record. Unlike
`dns-01`, which requires updating `DNS` records for every challenge,
`dns-persist-01` allows you to set the record once and reuse it forever.

## Rationale for Account Reuse

Because the persistent DNS record must explicitly bind the domain to a specific
ACME account (via the `accounturi` parameter), re-using the same ACME account
across your infrastructure becomes highly beneficial. It avoids the need to
provision separate DNS records for every acme client instance requesting
certificates for the same domain or subdomain.

## Setup Instructions

1.  Retrieve your Account URI:

    Use `acmecli.py` to find the `unique_uri` for your account. Your ACMEv2
    account is tied to the **public portion** of your private assymetric key:

    ```bash
    acmecli.py -k privatekey.pem account show

    Account URI: https://acme-staging-v02.api.letsencrypt.org/acme/acct/EXAMPLE12345
    ```

2.  Provision the DNS Record:

    Create a `TXT` record at `_validation-persist.<your-domain>`. The value must
    match the format defined in the draft, referencing the CA's issuer domain
    and your `accounturi`.

    *Example for "example.com" using Let's Encrypt:*

    ```text
    _validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/EXAMPLE12345"
    ```

3.  Issue Certificates

    Note: No ACMEv2 CA rolled out this challenge yet. It is planned for 2026.
    Also, no acme client supports this challenge (yet).

# Contributing

By submitting a contribution to be included in this project, you implicitly agree to licence your contribution under BSD 3-Clause Licence.

# TODO

* Investigate `NIST P-512` with `letsencrypt.org` and `pki.goog` as they seem
  not working

* design `certificate create` and `certificate revoke` commands, must write
  files to disk must generate private key for tls-server (if none prepared
  upfront), etc.

* must support ACMEv2 extension profiles

* must support ACMEv2 extension ACME Renewal Information

* challenge - initially copy uacme external program approach, so user can handle
  all possible challenges himself in order that ACMEv2 presents them.

* challenge - later focus on `http-01` (stateless) and `dns-persist-01`

