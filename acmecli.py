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


class JOSESigner:
    def __init__(self, key_path=None, key_content=None, kid=None):
        self.jwk = None
        self.alg = None
        
        # Load Content
        if key_path:
            with open(key_path, "rb") as f:
                content = f.read()
            if key_path.endswith(('.json', '.js')):
                self._load_json(content)
            else:
                self._load_auto(content)
        elif key_content:
            # Check if it is an HMAC bytes key (Octet) or standard key
            if isinstance(key_content, bytes) and kid:
                # EAB HMAC case
                self.jwk = jwk.OctKey.import_key(key_content, parameters={'kid': kid})
            else:
                self._load_auto(key_content)
        
        if not self.jwk:
            raise ValueError("Unable to load key")

        # Determine Algorithm
        self._set_algorithm()

    def _load_json(self, content):
        self.jwk = jwk.import_key(json.loads(content))

    def _load_auto(self, content):
        for keytype in ["RSA", "EC", "OKP"]:
            try:
                self.jwk = jwk.import_key(content, keytype)
                return
            except errors.InvalidKeyTypeError:
                continue

    def _set_algorithm(self):
        # Mapping per RFC 7518
        ec_algs = {
            "P-256": "ES256", "P-384": "ES384", 
            "P-521": "ES512", "Ed25519": "Ed25519"
        }
        if self.jwk.key_type == "RSA":
            self.alg = "RS256"
        elif self.jwk.key_type in ["EC", "OKP"]:
            self.alg = ec_algs.get(self.jwk.curve_name)
        elif self.jwk.key_type == "oct":
            self.alg = "HS256" 
        if not self.alg:
            raise ValueError("Unsupported private key type.")

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
        return self.jwk.as_pem().decode("ascii")

    def as_json(self):
        return json.dumps(self.jwk.as_dict(), indent=2)


class ACMEClient:
    def __init__(self, key_path, directory_url="https://acme-v02.api.letsencrypt.org/directory"):
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self.directory_url = directory_url
        self.key_path = key_path
        self.key = self.key = JOSESigner(key_path=key_path)
        self.session = requests.Session()
        self.nonce = None
        self.directory = None
        self.meta = {}
        self.external_account_required = False
        self.terms_of_service_url = None

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
            "alg": self.key.alg,
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
            hmac_key = JOSESigner(key_content=key_bytes, kid=eab_kid)
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
        #raise ACMEError("debug pause")
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
        if resp.status_code not in [200, 201]:
            error, error_msg = self._get_error(resp)
            if error == 'accountDoesNotExist':
                raise accountDoesNotExist(f"{error}: {error_msg}")
            else:
                raise ACMEError(f"Failed to retrieve account: {error}: {error_msg}")
        return resp.headers.get('Location'), resp.json()

    def thumbprint(self):
        return self.key.get_thumbprint()

    def get_private_key(self, format="pem"):
        if format == "pem":
            return self.key.as_pem().decode("ascii")
        elif format == "json":
            return json.dumps(self.key.as_dict(), indent=2)
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
        if resp.status_code != 200:
            error, error_msg = self._get_error(resp)
            print(f"Update failed. {error}: {error_msg}")
        else:
            print("Account updated successfully.")
            print(json.dumps(resp.json(), indent=2))

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

    def change_account_key(self, new_key_path):
        """
        RFC 8555 7.3.5: Account Key Rollover
        """
        if not self.directory:
            self._get_directory()
        key_change_url = self.directory.get('keyChange')
        if not key_change_url:
            raise ACMEError("Server does not support keyChange.")
        try:
            new_key_signer = JOSESigner(key_path=new_key_path)
        except Exception as e:
            raise ValueError(f"Failed to load new key from {new_key_path}: {e}")

        account_url, _ = self.get_account()

        self.logger.debug("Account rekeying. Creating inner payload.")
        inner_payload = {
            "account": account_url,
            "oldKey": self.key.get_public_jwk()
        }
        inner_payload_json = json.dumps(inner_payload, separators=(',', ':'))
        inner_protected_header = {
            "alg": new_key_signer.alg,
            "jwk": new_key_signer.get_public_jwk(),
            "url": key_change_url
        }
        inner_jws = new_key_signer.sign(inner_protected_header, inner_payload_json)
        self.logger.debug(f"inner_jws: {json.dumps(inner_jws)}")

        self.logger.debug(f"Sending rekey request to {key_change_url}")        
        resp = self._request("POST", key_change_url, inner_jws, kid=account_url)
        if resp.status_code == 200:
            print("Key rollover successful.")
            print(json.dumps(resp.json(), indent=2))
        else:
            error, error_msg = self._get_error(resp)
            raise ACMEError(f"Key rollover failed. {error}: {error_msg}")

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
        if args.details:
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

def cli_account_rekey(client: ACMEClient, args):
    if not os.path.exists(args.new_key):
        print(f"Error: New key file not found at {args.new_key}")
        sys.exit(1)
    try:
        account_uri, _ = client.get_account()
    except accountDoesNotExist:
        print(f"Unable to rekey: no account exist with the provided key {client.key_path}")
        sys.exit(1)
    print(f"Rolling over new key for account {account_uri}")
    print(f"Old Key: {client.key_path}")
    print(f"New Key: {args.new_key}")    
    try:
        client.change_account_key(args.new_key)
    except ACMEError as ex:
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
    print(f"Your public thumbprint: {thumbprint}")
    message = """

   Thumbprint - A hash of the public key (per RFC-8555 § 8.3). It is not secret;
   anyone may know it without compromising the account. It is retrived from a
   *public* component of your asymmetric key.

""".format(thumbprint)
    if args.details:
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
    show_parser = account_subparsers.add_parser("show", help="Show account details")
    show_parser.add_argument("-d", "--details", action='store_true')
    update_parser = account_subparsers.add_parser("update", help="Update account contacts")
    update_parser.add_argument("contacts", nargs="+", help="List of contacts (e.g., mailto:x@y.z) or 'clear'")
    create_parser = account_subparsers.add_parser("create", help="Create new account")
    create_parser.add_argument("contacts", nargs="*", help="List of contacts (e.g., mailto:x@y.z)", default=[])
    create_parser.add_argument("--eab-kid", help="Key Identifier for External Account Binding")
    create_parser.add_argument("--eab-hmac-key", help="HMAC Key for External Account Binding (Base64Url)")
    create_parser.add_argument("--eab-alg", choices=["HS256", "HS384", "HS512"], default="HS256", help="Algorithm for EAB (default: HS256)")
    group = create_parser.add_mutually_exclusive_group()
    group.add_argument("--agree-tos", action="store_true", help="Agree to Terms of Service automatically")
    rekey_parser = account_subparsers.add_parser("rekey", help="Change account keys (Rollover)")
    rekey_parser.add_argument("new_key", type=str, help="Path to the NEW private key file")
    deactivate_parser = account_subparsers.add_parser("deactivate", help="Deactivate account")
    deactivate_parser.add_argument("--confirm", action="store_true", help="Confirm deactivation without prompts")
    # Key Parse
    key_parser = subparsers.add_parser("key", help="Key operations")
    key_subparsers = key_parser.add_subparsers(dest="key_action", required=True)
    thumbprint_parser = key_subparsers.add_parser("thumbprint", help="Print key thumbprint")
    thumbprint_parser.add_argument("-d", "--details", action='store_true')
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


    try:
        client = ACMEClient(args.key, directory_url=acme_url)

        if args.main_action == "account":
            if args.account_action == "show":
                cli_account_show(client, args)
            elif args.account_action == "update":
                cli_account_update(client, args)
                client.update_contact(args.contacts)
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
                print(client.get_private_key(args.format))
    except ACMEError as ex:
        print(ex)
        sys.exit(1)

if __name__ == "__main__":
    cli()
