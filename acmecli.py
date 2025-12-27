#!/usr/bin/env python3

import argparse
import base64
import sys
import os
import json
import logging
import warnings
warnings.filterwarnings("ignore", message=".*urllib3.*only supports OpenSSL.*", module="urllib3")

try:
    import requests
    from joserfc import jws, jwk, errors
except ImportError:
    print("You're missing `requests` library. pip install requests")
    sys.exit(1)


class ACMEError(Exception):
    pass

class cliMustAccept(ACMEError):
    pass

class cliMissingArgument(ACMEError):
    pass
class externalAccountRequired(ACMEError):
    pass
class accountDoesNotExist(ACMEError):
    pass


class ACMEClient:
    def __init__(self, key_path, directory_url="https://acme-v02.api.letsencrypt.org/directory"):
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.directory_url = directory_url
        self.key_path = key_path
        self.jwk = None
        self.jwk_alg = None
        self._load_key()
        self.session = requests.Session()
        self.nonce = None
        self.directory = None
        self.meta = {}
        self.external_account_required = False
        self.terms_of_service_url = None

    def _load_key(self):
        self.logger.debug(f"Loading private key {self.key_path}")
        with open(self.key_path, "rb") as f:
            file_content = f.read()
        if self.key_path.endswith(('.json', '.js')):
            self.logger.debug(f"Initializing JWK from JSON")
            self.jwk = jwk.import_key(json.loads(file_content))
        else:
            for keytype in ["RSA", "EC", "OKP"]:
                try:
                    self.logger.debug(f"Initializing JWK of type {keytype}")
                    self.jwk = jwk.import_key(file_content, keytype)
                    break
                except errors.InvalidKeyTypeError:
                    pass
            if not self.jwk:
                raise Exception(f"Unable to load {self.key_path}")
        # set self.jwk_alg
        supported_ec_algorithms = {
            "P-256": "ES256",
            "P-384": "ES384",
            "P-521": "ES512",
            "Ed25519": "Ed25519"
        }
        try:
            if self.jwk.key_type == "RSA":
                self.jwk_alg = "RS256"
            elif self.jwk.key_type in ["EC", "OKP"]:
                crv = self.jwk.curve_name
                self.jwk_alg = supported_ec_algorithms[crv]
            else:
                raise("Unsupported private key type.")
        except KeyError:
            raise("Unsupported private key type.")
        self.logger.debug(f"JWK initialized: {self.jwk.key_type}")

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
            "alg": self.jwk_alg,
            "nonce": self._get_nonce(),
            "url": url
        }
        if kid:
            protected["kid"] = kid
        else:
            protected["jwk"] = self.jwk.as_dict(private=False)
        registry = jws.JWSRegistry(algorithms=[self.jwk_alg], strict_check_header=False)
        member = {"protected": protected}
        signed = jws.serialize_json(member, payload=payload_str_or_bytes, private_key=self.jwk, registry=registry)
        return signed

    def _request(self, method, url, payload, kid=None, allow_redirects=True):
        if not self.directory:
            self._get_directory()
        if isinstance(payload, dict):
            payload = json.dumps(payload, separators=(',', ':'))
        signed_data = self._sign(payload, url, kid)
        headers = {"Content-Type": "application/jose+json"}
        resp = self.session.request(method, url, json=signed_data, headers=headers, allow_redirects=allow_redirects)
        self.nonce = resp.headers.get('Replay-Nonce')
        return resp

    def _get_error(self, response):
        rfc8555_errors = {
            'accountDoesNotExist',
            'badNonce',
            'badPublicKey',
            'badSignatureAlgorithm',
            'compound',
            'externalAccountRequired',
            'invalidContact',
            'malformed',
            'rateLimited',
            'serverInternal',
            'unauthorized',
            'unsupportedContact'
        }
        if response.status_code >= 400:
            try:
                error = json.loads(response.text)
                type_uri = error["type"]
                type_ns = "urn:ietf:params:acme:error:"
                title = error.get("title")
                detail = error.get("detail", "")
                if title:
                    error_msg = f"{title}: {detail}"
                else:
                    error_msg = detail
                if not type_uri.startswith(type_ns):
                    return None, f"Unknown error type: {response.text}"
                type = type_uri[len(type_ns):]
                if type not in rfc8555_errors:
                    return None, f"Unsupported error type: {response.text}"
                return type, error_msg
            except (ValueError, KeyError):
                return None, f"Unknown error: {response.text}"
        else:
            return None, ""

    def get_account(self):
        if not self.directory:
            self._get_directory()
        self.logger.debug("Obtaining account.")
        payload = {"onlyReturnExisting": True}
        resp = self._request("POST", self.directory['newAccount'], payload, allow_redirects=False)
        if resp.status_code not in [200, 201]:
            error, error_msg = self._get_error(resp)
            if error == 'accountDoesNotExist':
                raise accountDoesNotExist(f"{error}: {error_msg}")
            else:
                raise ACMEError(f"Failed to retrieve account: {error}: {error_msg}")
        return resp.headers.get('Location'), resp.json()

    def thumbprint(self):
        return self.jwk.thumbprint()

    def get_metadata(self):
        if not self.directory:
            self._get_directory()
        return {
            "url": self.directory_url,
            "terms_of_service_url": self.terms_of_service_url,
            "external_account_required": self.external_account_required,
            "meta": self.meta,
        }

    def get_private_key(self, format="pem"):
        if format == "pem":
            return self.jwk.as_pem().decode("ascii")
        elif format == "json":
            return json.dumps(self.jwk.as_dict(), indent=2)
        else:
            raise ValueError(f"Unknown private key format: {format}")

    def get_public_key(self, format="pem"):
        raise NotADirectoryError

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
        if resp.status_code != 200:
            error, error_msg = self._get_error(resp)
            print(f"Update failed. {error}: {error_msg}")
        else:
            print("Account updated successfully.")
            print(json.dumps(resp.json(), indent=2))

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
            mac_jwk = jwk.OctKey.import_key(key_bytes, parameters={'kid': eab_kid})
            self.logger.debug(f"OctKey: {json.dumps(mac_jwk.as_dict(), indent=2)}")
        except Exception as e:
            raise ValueError(f"Failed to import HMAC key: {e}")

        payload = json.dumps(self.jwk.as_dict(private=False), separators=(',', ':'))
        protected = {
            "alg": eab_alg,
            "kid": eab_kid,
            "url": url
        }
        registry = jws.JWSRegistry(algorithms=[eab_alg], strict_check_header=False)
        member = {"protected": protected}
        signed = jws.serialize_json(member, payload=payload, private_key=mac_jwk, registry=registry)
        return signed

    def create_account(self, contacts, eab_kid=None, eab_hmac_key=None, eab_alg="HS256", agree_tos=False):
        if not self.directory:
            self._get_directory()

        try:
            account_url, _ = self.get_account()
            raise ACMEError(f"Account already created: {account_url}")
        except accountDoesNotExist:
            pass

        # Check EAB Requirements
        if self.external_account_required and not (eab_kid and eab_hmac_key):
            raise ACMEError("This ACMEv2 server required External Account Binding.")

        payload = {}
        if contacts:
            payload["contact"] = contacts
        if agree_tos:
            payload["termsOfServiceAgreed"] = True

        # Handle EAB
        if eab_kid and eab_hmac_key:
            self.logger.debug(f"Calculating EAB using {eab_alg}")
            try:
                # The URL in EAB must match the request URL
                new_account_url = self.directory['newAccount']
                eab_jws = self._sign_eab(eab_kid, eab_hmac_key, eab_alg, new_account_url)
                payload["externalAccountBinding"] = eab_jws
            except ValueError as e:
                print(f"EAB Error: {e}")
                sys.exit(1)

        self.logger.debug(f"Creating account with payload: {payload}")
        resp = self._request("POST", self.directory['newAccount'], payload, allow_redirects=False)

        if resp.status_code in [200, 201]:
            print("Account created/retrieved successfully.")
            account_url = resp.headers.get('Location')
            print(f"Account URI: {account_url}")
            print("Account Data:")
            print(json.dumps(resp.json(), indent=2))
        else:
            error, error_msg = self._get_error(resp)
            print(f"Account creation failed. {error}: {error_msg}")

    def deactivate_account(self, confirm=False):
        account_url, _ = self.get_account()
        if not confirm:
            raise cliMustAccept("Deactivation requires confirmation from the user.")
        payload = {"status": "deactivated"}
        self.logger.info(f"Deactivating account {account_url}")
        resp = self._request("POST", account_url, payload, kid=account_url)
        if resp.status_code == 200:
            print("Account deactivated successfully.")
            print(json.dumps(resp.json(), indent=2))
        else:
            error, error_msg = self._get_error(resp)
            print(f"Deactivation failed. {error}: {error_msg}")

def cli_account_show(client: ACMEClient, args):
    try:
        account_uri, account_data = client.get_account()
        print(f"Account URI: {account_uri}")
        print(f"Account status: {account_data.get('status')}")
        print("Account data:")
        print(json.dumps(account_data, indent=2))
    except Exception as ex:
        print(ex)

def cli_account_update(client: ACMEClient, args):
    try:
        client.update_contact(args.contacts)
    except accountDoesNotExist as ex:
        print(ex)
        sys.exit(1)

def cli_account_create(client: ACMEClient, args):
    try:
        account_uri, _ = client.get_account()
        print(f"Account already exist: {account_uri}")
        sys.exit(0)
    except accountDoesNotExist:
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
        client.create_account(
            contacts=args.contacts,
            eab_kid=args.eab_kid,
            eab_hmac_key=args.eab_hmac_key,
            eab_alg=args.eab_alg,
            agree_tos=args.agree_tos
        )
    except externalAccountRequired as ex:
        print(f"Unable to create account, {acme.get('url')} requires External Account Binding:")
        print(ex)
        sys.exit(1)

def cli_account_deactivate(client: ACMEClient, args):
    try:
        account_uri, _ = client.get_account()
    except accountDoesNotExist:
        print("Can't deactivate: account does not exist.")
        sys.exit(0)
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
    client.deactivate_account(confirm=args.confirm)

def cli_key_thumbprint(client: ACMEClient, args):
    thumbprint = client.thumbprint()
    message = """Your public thumbprint: {0}

Your thumbprint is calculated from the public portion of your private asymetric key.
Thumbprint is not a secret and revealing it does not compromise your ACME account.
You can use it to setup a stateless http-01 challenge, as per RFC8555 Section 8.3
the token from the challenge is part of the URL accessed. Therefore, challenge can be
pre-computed entirely by your HTTP server without uploading any files to pass
the challenge.

When to use:
* if you want to run acme client on a different machine than serving your http traffic,
* when you have traffic distributed over multiple machines and uploading a challenge
  file to all of them would be error-prone and unreliable,
* perfect if you have LoadBalancer in front of multiple web servers that auto-scale
* perfect for Openshift /  Kubernetes, where you don't have to modify
  Ingress/HTTPRoute/Route object to pass the challenge,
* perfect if you operate a small geo-distributed CDN with lots of web servers
  and you need to be sure all of them always pass the challenge.

Risk:
When implemented incorrectly, you are risking cross-site vulnerability. Examples
provided bellow do not allow cross-site HTML tags being passed using a regexp.

How to set this up:
nginx:
    http {{
    ...
        server {{
        listen 80;
        ...
            location ~ ^/\.well-known/acme-challenge/([-_a-zA-Z0-9]+)$ {{
            default_type text/plain;
            return 200 "$1.{0}";
            }}
        ...
        }}
    }}

apache2:
    <VirtualHost *:80>
        ...
        <LocationMatch "/.well-known/acme-challenge/(?<challenge>[-_a-zA-Z0-9]+)">
            RewriteEngine On
            RewriteRule "^([-_a-zA-Z0-9]+)$" "$1" [E=challenge:$1]
            ErrorDocument 200 "%{{ENV:MATCH_CHALLENGE}}.{0}"
            RewriteRule ^ - [L,R=200]
        </LocationMatch>
        ...
    </VirtualHost>
""".format(thumbprint)
    print(message)


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

    account_subparsers.add_parser("show", help="Show account details")

    update_parser = account_subparsers.add_parser("update", help="Update account contacts")
    update_parser.add_argument("contacts", nargs="+", help="List of contacts (e.g., mailto:x@y.z) or 'clear'")

    create_parser = account_subparsers.add_parser("create", help="Create new account")
    create_parser.add_argument("contacts", nargs="*", help="List of contacts (e.g., mailto:x@y.z)", default=[])
    create_parser.add_argument("--eab-kid", help="Key Identifier for External Account Binding")
    create_parser.add_argument("--eab-hmac-key", help="HMAC Key for External Account Binding (Base64Url)")
    create_parser.add_argument("--eab-alg", choices=["HS256", "HS384", "HS512"], default="HS256", help="Algorithm for EAB (default: HS256)")
    group = create_parser.add_mutually_exclusive_group()
    group.add_argument("--agree-tos", action="store_true", help="Agree to Terms of Service automatically")

    deactivate_parser = account_subparsers.add_parser("deactivate", help="Deactivate account")
    deactivate_parser.add_argument("--confirm", action="store_true", help="Confirm deactivation without prompts")
    # Key Parse
    key_parser = subparsers.add_parser("key", help="Key operations")
    key_subparsers = key_parser.add_subparsers(dest="key_action", required=True)
    key_subparsers.add_parser("thumbprint", help="Print key thumbprint")
    convert_parser = key_subparsers.add_parser("convert", help="Convert key format")
    convert_parser.add_argument("format", choices=["pem", "json"], help="Output format")
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

    client = ACMEClient(args.key, directory_url=acme_url)

    if args.main_action == "account":
        if args.account_action == "show":
            cli_account_show(client, args)
        elif args.account_action == "update":
            cli_account_update(client, args)
            client.update_contact(args.contacts)
        elif args.account_action == "create":
            cli_account_create(client, args)
        elif args.account_action == "deactivate":
            cli_account_deactivate(client, args)
    elif args.main_action == "key":
        if args.key_action == "thumbprint":
            cli_key_thumbprint(client, args)
        elif args.key_action == "convert":
            print(client.get_private_key(args.format))

if __name__ == "__main__":
    cli()
