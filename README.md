# acmecli.py

This tiny `acmecli.py` client is focused on ACMEv2 account management. You can
create, show, update, rekey and deactivate your account. It will also assist
you with setting up stateless challenges, like `http-01` or `dns-persistent-01`.

You can also use this tool to migrate from one acme client to another, or re-use
your acme account by multiple clients or machines. The rationale behind ACME
account re-use is explained in section *Stateless dns-persisnt-01*.

This tiny `acmecli.py` uses upstream libraries to deal with cryptographics
and network communication:
* [authlib/joserfc](https://github.com/authlib/joserfc) - [jose.authlib.org](https://jose.authlib.org/en/)
* [psf/requests](https://github.com/psf/requests) - [requests.readthedocs.io](https://requests.readthedocs.io/en/latest/)

This tool intentionally does not create any `key.pem` files. To keep the
codebase simple and avoid any security conerns related to key creation, you have
to create your private key yourself. Examples are provided for `openssl`.

This tiny `acmecli.py` does not obtains any certficate on its own yet. Adding this
functionality is planned at a later date. As this is an early stage of the
project, API is not frozed and may be changed without notice.

## Usage

```
Usage:

acmecli.py [-a ACME_URL] -k key.(pem|json) account show [-d|-detail]
    Shows your account URI and other details reported by ACMEv2 server.

acmecli.py [-a ACME_URL] -k key.(pem|json) account create --help
    Create new ACMEv2 account. Before running this, create key.pem upfront.

acmecli.py [-a ACME_URL] -k key.(pem|json) account update \
[mailto:user@example.com mailto:admin@example.net ... | clear]
    Update your contact details. Contacts is a list.
    Prefix each contact with `mailto:`
    WARNING: magic word `clear` will clear all your current contacts.
    Per RFC 8555, contacts are OPTIONAL, but pki.goog requires at
    least one contact.

acmecli.py [-a ACME_URL] -k key.(pem|json) account rekey new.(pem|json)
    Your ACMEv2 account may allows you to re-key it with another private key.
    WARNING: This will change your thumbprint but keep your current account_uri.

acmecli.py [-a ACME_URL] -k key.(pem|json) account deactivate
    WARNING: This will permanently deactivate your account_uri AND your private key.
    You won't be able to re-use this private key again on this ACMEv2 server, ever.

acmecli.py [-a ACME_URL] -k key.(pem|json) key thumbprint [-d|--detail]
    Print your thumbprint. Used for stateless `http-01` challenger. See bellow.

acmecli.py [-a ACME_URL] -k key.(pem|json) key convert <pem|json>
    Migrate from one acme client to another if they require a different key format.
    TIP: Most acme clients use `pem` format, but `certbot` uses JSON Web Key format.

```

Global parameters:
```
ACME_URL must be one of:
* Full url to your ACMEv2 directory, or
* short word: [letsencrypt | letsencrypt-staging | goog | goog-staging]

ACME_URL default value: letsencrypt.org production ACMEv2:
https://acme-v02.api.letsencrypt.org/directory
```

## Create account

First, create your private key. Pick your type:

```
# RSA key
openssl genrsa -out rsa.pem 3072

# ECDSA - NIST P-256
openssl ecparam -name prime256v1 -noout -genkey -out p256.pem

# ECDSA - NIST P-384
openssl ecparam -name secp384r1 -noout -genkey -out p384.pem

# ECDSA - NIST P-521
openssl ecparam -name secp521r1 -noout -genkey -out p521.pem

# Ed25519
openssl genpkey -algorithm ed25519 -out ed25519.pem
```

Beware that most ACMEv2 servers only support `RSA` and `P-256`.

Then, proceed to create your account on the ACMEv2 server:
```
acmecli.py -k yourkey.pem account create
```

## Rekey account

First, generate your `newkey.pem` with openssl (see above).
It does not have to be the same type as previously.

```
acmecli.py -k oldkey.pem account rekey newkey.pem
```


## Private key conversion

## Stateless http-01

## Stateless dns-persist-01
