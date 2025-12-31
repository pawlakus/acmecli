#!/usr/bin/env python3

import argparse
import base64
import sys
import os
import json
import logging
import warnings

try:
    # Hack: Supress warning on MacOS xcode-cli-tools python3.9 linked against MacOS libressl.
    # Have to supress it before importing `requests`, because it fires in urllib3/__init__.py
    warnings.filterwarnings("ignore", message=".*urllib3.*only supports OpenSSL.*", module="urllib3")
    import requests
    from joserfc import jws, jwk, errors
    import cryptography.hazmat.primitives.serialization as crypto_hps
    from joserfc import __version__ as joserfc_version



except ImportError:
    print("You're missing `requests` library. pip install requests")
    sys.exit(1)


__url__ = "https://github.com/pawlakus/acmecli"
__version__ = "0.1-dev"

############
# ACMEClient
############

class ACMEError(Exception):pass
class ACMEClientError(ACMEError):pass

class ACMEProtocolError(ACMEError):
    def __init__(self, response):
        self.status_code = response.status_code
        self.raw_text = response.text
        try:
            self.problem = response.json()
        except ValueError:
            self.problem = {}
        self.type_urn = self.problem.get("type", "unknown:urn")
        self.title = self.problem.get("title", "unknown")
        self.detail = self.problem.get("detail", self.raw_text)
        self.subproblems = self.problem.get("subproblems", [])
        if self.subproblems:
            msg = f"{self.status_code} {self.type_urn}: {self.title} - {self.detail} (Subproblems: {len(self.subproblems)})"
        else:
            msg = f"{self.status_code} {self.type_urn}: {self.title} - {self.detail}"
        super().__init__(msg)

class ACMEAccountDoesNotExist(ACMEProtocolError): pass
class ACMEAlreadyRevoked(ACMEProtocolError): pass
class ACMEBadCSR(ACMEProtocolError): pass
class ACMEBadNonce(ACMEProtocolError): pass
class ACMEBadPublicKey(ACMEProtocolError): pass
class ACMEBadRevocationReason(ACMEProtocolError): pass
class ACMEBadSignatureAlgorithm(ACMEProtocolError): pass
class ACMECAAError(ACMEProtocolError): pass
class ACMECompoundError(ACMEProtocolError): pass
class ACMEConnectionError(ACMEProtocolError): pass
class ACMEDNSError(ACMEProtocolError): pass
class ACMEExternalAccountRequired(ACMEProtocolError): pass
class ACMEIncorrectResponse(ACMEProtocolError): pass
class ACMEInvalidContact(ACMEProtocolError): pass
class ACMEMalformed(ACMEProtocolError): pass
class ACMEOrderNotReady(ACMEProtocolError): pass
class ACMERateLimited(ACMEProtocolError): pass
class ACMERejectedIdentifier(ACMEProtocolError): pass
class ACMEServerInternal(ACMEProtocolError): pass
class ACMETLSError(ACMEProtocolError): pass
class ACMEUnauthorized(ACMEProtocolError): pass
class ACMEUnsupportedContact(ACMEProtocolError): pass
class ACMEUnsupportedIdentifier(ACMEProtocolError): pass
class ACMEUserActionRequired(ACMEProtocolError): pass

ERROR_MAP = {
    "accountDoesNotExist": ACMEAccountDoesNotExist,
    "alreadyRevoked": ACMEAlreadyRevoked,
    "badCSR": ACMEBadCSR,
    "badNonce": ACMEBadNonce,
    "badPublicKey": ACMEBadPublicKey,
    "badRevocationReason": ACMEBadRevocationReason,
    "badSignatureAlgorithm": ACMEBadSignatureAlgorithm,
    "caa": ACMECAAError,
    "compound": ACMECompoundError,
    "connection": ACMEConnectionError,
    "dns": ACMEDNSError,
    "externalAccountRequired": ACMEExternalAccountRequired,
    "incorrectResponse": ACMEIncorrectResponse,
    "invalidContact": ACMEInvalidContact,
    "malformed": ACMEMalformed,
    "orderNotReady": ACMEOrderNotReady,
    "rateLimited": ACMERateLimited,
    "rejectedIdentifier": ACMERejectedIdentifier,
    "serverInternal": ACMEServerInternal,
    "tls": ACMETLSError,
    "unauthorized": ACMEUnauthorized,
    "unsupportedContact": ACMEUnsupportedContact,
    "unsupportedIdentifier": ACMEUnsupportedIdentifier,
    "userActionRequired": ACMEUserActionRequired,
}


class JOSESigner:
    def __init__(self, jwk_obj):
        """
        Use JOSESigner.load() to create instances from files.
        """
        self.jwk = jwk_obj
        self.alg = None
        self.crv = None
        self._set_algorithm()

    @classmethod
    def load(cls, file_path):
        if not os.path.exists(file_path):
            raise ACMEClientError(f"Key file not found: {file_path}")
        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except OSError as e:
            raise ACMEClientError(f"Error reading key file: {e}")
        try:
            data = json.loads(content)
            jwk_obj = jwk.import_key(data)
            return cls(jwk_obj)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # Not JSON
        for keytype in ["RSA", "EC", "OKP"]:
            try:
                jwk_obj = jwk.import_key(content, keytype)
                return cls(jwk_obj)
            except errors.InvalidKeyTypeError:
                continue
        raise ACMEClientError("Unable to identify key format (Valid: PEM or JWK/JSON)")

    @classmethod
    def from_bytes(cls, content):
        """Used for checking EAB HMAC keys (Octet)"""
        jwk_obj = jwk.OctKey.import_key(content)
        return cls(jwk_obj)

    def _set_algorithm(self):
        # Mapping per RFC 7518
        ec_algs = {
            "P-256": "ES256", "P-384": "ES384",
            "P-521": "ES512", "Ed25519": "EdDSA"
        }
        if self.jwk.key_type == "RSA":
            self.alg = "RS256"
        elif self.jwk.key_type in ["EC", "OKP"]:
            try:
                self.alg = ec_algs[self.jwk.curve_name]
                self.crv = self.jwk.curve_name
            except KeyError:
                raise ACMEClientError(f"Unsupported curve type: {self.jwk.curve_name}")
        elif self.jwk.key_type == "oct":
            self.alg = "HS256"
        else:
            raise ACMEClientError("Unsupported private key type.")

    def sign(self, protected_header, payload_str_or_bytes):
        if "alg" not in protected_header:
            protected_header["alg"] = self.alg
        registry = jws.JWSRegistry(algorithms=[protected_header["alg"]], strict_check_header=False)
        member = {"protected": protected_header}
        return jws.serialize_json(member, payload=payload_str_or_bytes, private_key=self.jwk, registry=registry)

    def get_public_jwk(self):
        return self.jwk.as_dict(private=False)

    def get_thumbprint(self):
        return self.jwk.thumbprint()

    def as_pem(self):
        return self.jwk.as_pem()

    def as_json(self):
        return json.dumps(self.jwk.as_dict(), indent=2)


class ACMEClient:
    def __init__(self, signer: JOSESigner, directory_url="https://acme-v02.api.letsencrypt.org/directory"):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.directory_url = directory_url
        self.key = signer
        self.session = requests.Session()
        self.session.headers['User-Agent'] = f"acmecli/{__version__} ({__url__}) joserfc/{joserfc_version}"
        self.account_uri = None
        self.nonce = None
        self.directory = None
        self.meta = {}
        self.external_account_required = False
        self.terms_of_service_url = None

    def _check_response(self, response):
        if 200 <= response.status_code < 300:
            return
        try:
            problem = response.json()
            urn = problem.get("type", "")
        except ValueError:
            raise ACMEProtocolError(response)

        namespace = "urn:ietf:params:acme:error:"
        if urn.startswith(namespace):
            short_type = urn[len(namespace):]
            if short_type in ERROR_MAP:
                raise ERROR_MAP[short_type](response)
        # Generic fallback for unknown URNs or non-standard errors
        raise ACMEProtocolError(response)

    def _get_directory(self):
        self.logger.debug("Obtaining directory json.")
        resp = self.session.get(self.directory_url)
        self.nonce = resp.headers.get('Replay-Nonce')
        self.directory = resp.json()
        self.meta = self.directory.get("meta", {})
        self.external_account_required = self.meta.get("externalAccountRequired", False)
        self.terms_of_service_url = self.meta.get("termsOfService")

    def _get_nonce(self):
        if not self.directory:
            self._get_directory()
        if not self.nonce:
            self.logger.debug("Acquiring new once.")
            resp = self.session.head(self.directory['newNonce'])
            return resp.headers['Replay-Nonce']
        nonce = self.nonce
        self.nonce = None
        return nonce

    def _sign(self, payload_str_or_bytes, url, kid=None):
        protected = {
            "nonce": self._get_nonce(),
            "url": url
        }
        if kid:
            protected["kid"] = kid
        else:
            protected["jwk"] = self.key.get_public_jwk()
        return self.key.sign(protected, payload_str_or_bytes)

    def _sign_eab(self, eab_kid, eab_hmac_key, eab_alg, url):
        """
        RFC 8555 7.3.4 External Account Binding
        Returns the standard JWS binding object.
        """
        # Add padding if necessary
        pad = len(eab_hmac_key) % 4
        if pad > 0:
            eab_hmac_key += '=' * (4 - pad)

        try:
            key_bytes = base64.urlsafe_b64decode(eab_hmac_key)
        except Exception:
            raise ValueError("EAB HMAC key must be base64url encoded.")

        try:
            hmac_key = JOSESigner.from_bytes(key_bytes)
            hmac_key.alg = eab_alg
        except Exception as e:
            raise ValueError(f"Failed to import HMAC key: {e}")

        payload = json.dumps(self.key.get_public_jwk(), separators=(',', ':'))
        protected = {
            "alg": eab_alg,
            "kid": eab_kid,
            "url": url
        }
        return hmac_key.sign(protected, payload)

    def _request(self, method, url, payload, kid=None, allow_redirects=True):
        if not self.directory:
            self._get_directory()
        if isinstance(payload, dict):
            payload = json.dumps(payload, separators=(',', ':'))
        signed_data = self._sign(payload, url, kid)
        self.logger.debug(json.dumps(signed_data, indent=2))
        headers = {"Content-Type": "application/jose+json"}
        resp = self.session.request(method, url, json=signed_data, headers=headers, allow_redirects=allow_redirects)
        self.nonce = resp.headers.get('Replay-Nonce')
        self._check_response(resp)
        return resp

    def get_metadata(self):
        if not self.directory:
            self._get_directory()
        return {
            "url": self.directory_url,
            "terms_of_service_url": self.terms_of_service_url,
            "external_account_required": self.external_account_required,
            "meta": self.meta,
        }

    def get_account(self):
        if not self.directory:
            self._get_directory()
        self.logger.debug("Obtaining account.")
        payload = {"onlyReturnExisting": True}
        resp = self._request("POST", self.directory['newAccount'], payload, allow_redirects=False)
        return resp.headers.get('Location'), resp.json()

    def thumbprint(self):
        return self.key.get_thumbprint()

    def get_private_key(self, format="pem"):
        if format == "pem":
            return self.key.as_pem()
        elif format in {"pkcs1", "pkcs8", "der1", "der8"}:
            crypto_encoding = crypto_hps.Encoding.PEM
            if format.startswith("der"): crypto_encoding = crypto_hps.Encoding.DER
            crypto_format = crypto_hps.PrivateFormat.PKCS8
            if format in {"pkcs1", "der1"}: crypto_format = crypto_hps.PrivateFormat.TraditionalOpenSSL
            raw = self.key.jwk.raw_value
            return raw.private_bytes(
                encoding=crypto_encoding,
                format=crypto_format,
                encryption_algorithm=crypto_hps.NoEncryption()
            )
        elif format == "json":
            return self.key.as_json()
        else:
            raise ValueError(f"Unknown private key format: {format}")

    def update_contact(self, contacts):
        account_url, _ = self.get_account()
        if len(contacts) == 1 and contacts[0].lower() == "clear":
            payload_contacts = []
        else:
            payload_contacts = contacts
        payload = {"contact": payload_contacts}
        self.logger.debug(f"Updating account with: {payload}")
        # RFC 8555 7.3.2: Account Update
        resp = self._request("POST", account_url, payload, kid=account_url)
        return resp.json()

    def create_account(self, contacts, eab_kid=None, eab_hmac_key=None, eab_alg="HS256", agree_tos=False):
        if not self.directory:
            self._get_directory()

        try:
            account_url, _ = self.get_account()
            raise ACMEClientError(f"Account already created: {account_url}")
        except ACMEAccountDoesNotExist:
            pass

        payload = {}
        if contacts:
            payload["contact"] = contacts
        if agree_tos:
            payload["termsOfServiceAgreed"] = True

        # Handle EAB
        if eab_kid and eab_hmac_key:
            self.logger.debug(f"Calculating EAB using {eab_alg}")
            try:
                new_account_url = self.directory['newAccount']
                eab_jws = self._sign_eab(eab_kid, eab_hmac_key, eab_alg, new_account_url)
                payload["externalAccountBinding"] = eab_jws
            except Exception as ex:
                raise ACMEClientError(f"EAB Calculation Failed: {ex}")

        self.logger.debug(f"Creating account with payload: {payload}")
        resp = self._request("POST", self.directory['newAccount'], payload, allow_redirects=False)
        return resp.headers.get('Location'), resp.json()

    def change_account_key(self, new_key_signer: JOSESigner):
        """
        RFC 8555 7.3.5: Account Key Rollover
        """
        if not self.directory:
            self._get_directory()
        key_change_url = self.directory.get('keyChange')
        if not key_change_url:
            raise ACMEClientError("Server does not support keyChange endpoint.")
        account_url, _ = self.get_account()
        inner_payload = {
            "account": account_url,
            "oldKey": self.key.get_public_jwk()
        }
        inner_jws = new_key_signer.sign(
            protected_header={
                "alg": new_key_signer.alg,
                "jwk": new_key_signer.get_public_jwk(),
                "url": key_change_url
            },
            payload_str_or_bytes=json.dumps(inner_payload, separators=(',', ':'))
        )
        resp = self._request("POST", key_change_url, inner_jws, kid=account_url)
        return resp.json()

    def deactivate_account(self, confirm=False):
        account_url, _ = self.get_account()
        if not confirm:
            raise ACMEClientError("Deactivation requires confirmation.")
        payload = {"status": "deactivated"}
        self.logger.info(f"Deactivating account {account_url}")
        resp = self._request("POST", account_url, payload, kid=account_url)
        return resp.json()


#######
# CLI
#######


def cli_account_show(client: ACMEClient, args):
    try:
        account_uri, account_data = client.get_account()
        print(f"Account URI: {account_uri}")
        if args.details:
            print(f"Account status: {account_data.get('status')}")
            print("Account data:")
            print(json.dumps(account_data, indent=2))
    except ACMEAccountDoesNotExist as ex:
        print(f"Error: Account does not exist: {ex}", file=sys.stderr)
        sys.exit(1)
    except ACMEUnauthorized as ex:
        print(f"Error: Unauthorized: {ex}", file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)

def cli_account_update(client: ACMEClient, args):
    try:
        account_uri, _ = client.get_account()
        response_data = client.update_contact(args.contacts)
        print(f"Account updated: {account_uri}")
        print(f"New contacts: {args.contacts}")
        print(json.dumps(response_data, indent=2))
    except ACMEAccountDoesNotExist as ex:
        print(f"Error: Account does not exist: {ex}", file=sys.stderr)
        sys.exit(1)
    except ACMEUnauthorized as ex:
        print(f"Error: Unauthorized: {ex}", file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)

def cli_account_create(client: ACMEClient, args):
    try:
        account_uri, _ = client.get_account()
        print(f"Account already exist: {account_uri}")
        sys.exit(0)
    except ACMEAccountDoesNotExist:
        pass
    acme = client.get_metadata()
    if acme.get('terms_of_service_url') and not args.agree_tos:
        print(f"Terms of Service exist: {client.terms_of_service_url}")
        user_input = input("Do you agree to the Terms of Service? (y/N): ")
        if user_input.lower() != 'y':
            print("You must agree to the Terms of Service to create an account.")
            sys.exit(1)
        args.agree_tos = True
    try:
        account_uri, account_data = client.create_account(
            contacts=args.contacts,
            eab_kid=args.eab_kid,
            eab_hmac_key=args.eab_hmac_key,
            eab_alg=args.eab_alg,
            agree_tos=args.agree_tos
        )
        print(f"Account created: {account_uri}")
        print(json.dumps(account_data, indent=2))
    except ACMEExternalAccountRequired as ex:
        print(f"Error: This ACMEv2 server required External Account Binding parameters.", file=sys.stderr)
        print(ex, file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)

def cli_account_rekey(client: ACMEClient, args):
    if not os.path.exists(args.new_key):
        print(f"Error: New key file not found at {args.new_key}")
        sys.exit(1)
    try:
        new_key_signer = JOSESigner.load(args.new_key)
    except ACMEClientError as ex:
        print(f"Error loading new key: {ex}", file=sys.stderr)
        sys.exit(1)
    try:
        account_uri, _ = client.get_account()
    except ACMEAccountDoesNotExist as ex:
        print(f"Error: Unable to rekey: no account exist with the provided key.")
        print(ex, file=sys.stderr)
        sys.exit(1)
    print(f"Rolling over new key for account: {account_uri}")
    print(f"Old Key: {args.key}")
    print(f"New Key: {args.new_key}")
    try:
        response_data = client.change_account_key(new_key_signer)
        print(f"Account rekeyed: {account_uri}")
        print(json.dumps(response_data, indent=2))
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)

def cli_account_deactivate(client: ACMEClient, args):
    try:
        account_uri, _ = client.get_account()
    except ACMEAccountDoesNotExist:
        print("Can not deactivate: account does not exist.")
        sys.exit(0)
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)

    if not args.confirm:
        print("!!! WARNING !!!")
        print(f"You are about to deactivate your ACME account: {account_uri}")
        print("Once deactivated, you will NOT be able to use this private key")
        print("on this ACME server ever again as it will be tied to this account.")
        print("This account status will change to 'deactivated' permanently.")
        print("WARNING: This action is irreversible.")
        print(f"WARNING: You will lose {account_uri} forever.")
        user_input = input("Are you sure you want to proceed? (y/N): ")
        if user_input.lower() != "y":
            print("Deactivation aborted by user.")
            sys.exit(0)
        args.confirm = True
    try:
        response_data = client.deactivate_account(confirm=args.confirm)
        print(f"Account deactivated: {account_uri}")
        print(json.dumps(response_data, indent=2))
    except Exception as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)

def cli_key_thumbprint(client: ACMEClient, args):
    thumbprint = client.thumbprint()
    print(f"Your public thumbprint: {thumbprint}")
    message = """

   Thumbprint - A hash of the public key (per RFC-8555 § 8.3). It is not secret;
   anyone may know it without compromising the account. It is retrived from a
   *public* component of your asymmetric key.

""".format(thumbprint)
    if args.details:
        print(message)

def cli_key_convert(client: ACMEClient, args):
    format = args.format.lower()
    response = client.get_private_key(format)
    if isinstance(response, bytes):
        if format in {'pem', 'pkcs1', 'pkcs8', 'json'}:
            print(response.decode("ascii"))
        else:
            print("Warning: Binary format chosen, sending binary to stdout. Redirect to a file.", file=sys.stderr)
            sys.stdout.buffer.write(response)
            sys.stdout.buffer.flush()
    else:
        print(response)

def cli():
    parser = argparse.ArgumentParser(
        prog="acmecli.py",
        description="ACME client helper."
    )
    parser.add_argument("-v", "--verbose", action='store_true', default=False)
    parser.add_argument("-a", "--acme-url", type=str, default="https://acme-v02.api.letsencrypt.org/directory")
    parser.add_argument("-k", "--key", type=str, required=True, help="Path to the private key file")
    subparsers = parser.add_subparsers(dest="main_action", required=True)
    # Account Parser
    account_parser = subparsers.add_parser("account", help="Account operations")
    account_subparsers = account_parser.add_subparsers(dest="account_action", required=True)
    show_parser = account_subparsers.add_parser("show", help="Show account details")
    show_parser.add_argument("-d", "--details", action='store_true')
    update_parser = account_subparsers.add_parser("update", help="Update account contacts")
    update_parser.add_argument("contacts", nargs="+", help="List of contacts (e.g., mailto:x@y.z) or 'clear'")
    create_parser = account_subparsers.add_parser("create", help="Create new account")
    create_parser.add_argument("contacts", nargs="*", help="List of contacts (e.g., mailto:x@y.z)", default=[])
    create_parser.add_argument("--eab-kid", help="Key Identifier for External Account Binding")
    create_parser.add_argument("--eab-hmac-key", help="HMAC Key for External Account Binding (Base64Url)")
    create_parser.add_argument("--eab-alg", choices=["HS256", "HS384", "HS512"], default="HS256", help="Algorithm for EAB (default: HS256)")
    create_parser.add_argument("--agree-tos", required=False, default=False, help="Agree to Terms of Service automatically")
    rekey_parser = account_subparsers.add_parser("rekey", help="Change account keys (Rollover)")
    rekey_parser.add_argument("new_key", type=str, help="Path to the NEW private key file")
    deactivate_parser = account_subparsers.add_parser("deactivate", help="Deactivate account")
    deactivate_parser.add_argument("--confirm", action="store_true", help="Confirm deactivation without prompts")
    # Key Parse
    key_parser = subparsers.add_parser("key", help="Key operations")
    key_subparsers = key_parser.add_subparsers(dest="key_action", required=True)
    thumbprint_parser = key_subparsers.add_parser("thumbprint", help="Print key thumbprint")
    thumbprint_parser.add_argument("-d", "--details", action='store_true')
    convert_parser = key_subparsers.add_parser("convert", help="Convert key format. Writes to stdout, even binary formats!")
    convert_parser.add_argument("format", choices=["pem", "json", "pkcs1", "pkcs8", "der1", "der8"], help="Output format. JSON, PEM (default), PEM PKCS#1 or PKCS#8, DER PKCS#1 or PKCS#8")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    # Resolve short ACME URL names
    acme_public_urls = {
        "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
        "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "goog": "https://dv.acme-v02.api.pki.goog/directory",
        "goog-staging": "https://dv.acme-v02.test-api.pki.goog/directory"
    }
    acme_url = args.acme_url
    for k in acme_public_urls:
        if acme_url.lower() == k:
            acme_url = acme_public_urls[k]

    # Private key is needed for every action
    if not os.path.exists(args.key):
        print(f"Error: Private key not found at {args.key}")
        sys.exit(1)

    try:
        signer = JOSESigner.load(args.key)
        client = ACMEClient(signer=signer, directory_url=acme_url)
        if args.main_action == "account":
            if args.account_action == "show":
                cli_account_show(client, args)
            elif args.account_action == "update":
                cli_account_update(client, args)
            elif args.account_action == "create":
                cli_account_create(client, args)
            elif args.account_action == "rekey":
                cli_account_rekey(client, args)
            elif args.account_action == "deactivate":
                cli_account_deactivate(client, args)
        elif args.main_action == "key":
            if args.key_action == "thumbprint":
                cli_key_thumbprint(client, args)
            elif args.key_action == "convert":
                cli_key_convert(client, args)
    except ACMEClientError as ex:
        print(f"ClientError: {ex}", file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(f"CRITICAL: Unhandled exception:", file=sys.stderr)
        print(ex, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    cli()
