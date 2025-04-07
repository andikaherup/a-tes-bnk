import base64
import json
import time
import hashlib
import secrets
import requests
import logging
from myinfo import settings as myinfo_settings
# from django.core.cache import cache
from django.utils.crypto import get_random_string
import os
import re
from jwcrypto import jwe, jwk, jws
from jwcrypto.jwk import JWK, JWKSet

log = logging.getLogger(__name__)


# ========== Myinfo v4 (JWKS) ===========


# def base64url_encode(data):
#     """
#     Base64URL encode binary data (identical to the Node.js implementation)
#     """
#     # Standard base64 encoding
#     encoded = base64.b64encode(data)
#     # Convert to string and replace characters for base64url
#     return encoded.decode('ascii').replace('+', '-').replace('/', '_').replace('=', '')

# def generate_code_verifier():
#     """
#     Generate a code verifier according to the MyInfo specification
#     This matches: base64URLEncode(crypto.randomBytes(32))
#     """
#     # Generate 32 random bytes
#     random_bytes = os.urandom(32)
#     # Base64URL encode the random bytes
#     verifier = base64url_encode(random_bytes)
#     return verifier

# def generate_code_challenge(code_verifier):
#     """
#     Generate a code challenge according to the MyInfo specification
#     This matches: base64URLEncode(crypto.createHash('sha256').update(codeVerifier).digest())
#     """
#     # Hash the verifier string (as UTF-8 bytes)
#     digest = sha256(code_verifier.encode('utf-8')).digest()
#     # Base64URL encode the hash
#     challenge = base64url_encode(digest)
#     return challenge

def is_valid_code_verifier(verifier):
    """
    Validate code verifier according to PKCE specifications
    """
    # Check length (between 43 and 128 characters)
    if not (43 <= len(verifier) <= 128):
        print(f"Invalid verifier length: {len(verifier)}")
        return False
    
    # Check that verifier only contains valid characters
    # Allowed: A-Z, a-z, 0-9, "-", "_" (base64url alphabet)
    if not re.match(r'^[A-Za-z0-9\-_]+$', verifier):
        print(f"Invalid verifier characters found in: {verifier}")
        return False
    
    return True

def base64url_encode(data):
    """Identical to the Node.js implementation"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    encoded = base64.b64encode(data)
    return encoded.decode('utf-8').replace('+', '-').replace('/', '_').replace('=', '')

def generate_code_verifier():
    """Generate a code verifier identical to Node.js crypto.randomBytes(32)"""
    random_bytes = os.urandom(32)
    # Convert to hex string exactly like Node.js
    verifier = random_bytes.hex()
    return verifier

def generate_code_challenge(code_verifier):
    """
    Generate a code challenge according to the MyInfo specification
    This matches: base64URLEncode(crypto.createHash('sha256').update(codeVerifier).digest())
    """
    # Hash the verifier string (as UTF-8 bytes)
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Base64URL encode the hash
    challenge = base64.urlsafe_b64encode(digest).decode('utf-8').replace('=', '')
    return challenge
        
def generate_ephemeral_session_keypair() -> JWK:
    sig_jwk = jwk.JWK.generate(kty="EC", crv="P-256", alg="ES256", use="sig")
    return sig_jwk


def generate_client_assertion(url: str, jkt_thumbprint: str) -> str:
    """See https://api.singpass.gov.sg/library/myinfo/developers/clientassertion"""
    now = int(time.time())
    payload = {
        "sub": myinfo_settings.MYINFO_CLIENT_ID,
        # generate unique randomstring on every client_assertion for jti
        "jti": get_random_string(40),
        "aud": url,
        "iss": myinfo_settings.MYINFO_CLIENT_ID,
        "iat": now,
        "exp": now + 300,  # expiry of client_assertion set to 5mins max
        "cnf": {
            "jkt": jkt_thumbprint,  # jkt thumbprint should match DPoP JWK used in the same request
        },
    }
    jws_key = jwk.JWK.from_json(myinfo_settings.MYINFO_PRIVATE_KEY_SIG)
    jws_token = jws.JWS(json.dumps(payload))
    jws_token.add_signature(
        jws_key, alg=None, protected={"typ": "JWT", "alg": "ES256", "kid": jws_key.thumbprint()}
    )
    sig = json.loads(jws_token.serialize())
    return f'{sig["protected"]}.{sig["payload"]}.{sig["signature"]}'


def generate_dpop_header(url: str, session_ephemeral_keypair, method="POST", ath=None) -> str:
    """
    DPoP Proof (JWT) containing the client's ephemeral public signing key that can be used to
    prove legit possession of the access_token issued.
    See: https://api.singpass.gov.sg/library/myinfo/developers/dpop
    """
    now = int(time.time())
    payload = {
        "htu": url,
        "htm": method,
        # generate unique randomstring on every client_assertion for jti
        "jti": get_random_string(40),
        "iat": now,
        "exp": now + 120,  # expiry of client_assertion set to 2mins max
    }
    if ath:
        payload["ath"] = ath  # add ath if passed in (required for /person call)

    ephemeral_private_key = session_ephemeral_keypair.export_private()
    jwk_public = session_ephemeral_keypair.export_public(as_dict=True)
    jwk_public.update(
        {
            "use": "sig",
            "alg": "ES256",
            "kid": session_ephemeral_keypair.thumbprint(),
        }
    )

    jws_key = jwk.JWK.from_json(ephemeral_private_key)
    jws_token = jws.JWS(json.dumps(payload))
    jws_token.add_signature(
        jws_key, alg=None, protected={"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk_public}
    )
    sig = json.loads(jws_token.serialize())
    return f'{sig["protected"]}.{sig["payload"]}.{sig["signature"]}'


def get_jwkset(key_url: str) -> JWKSet:
    """
    Retrieval of Myinfo JWKS should be cached for at least one hour and not retrieved for every JWT validation
    Reference: https://api.singpass.gov.sg/library/myinfo/developers/implementation-technical-requirements
    """
    # TODO: configure CACHES backend in Django
    # cache_key = f"myinfo::jwkset::{key_url}"
    # keys_data = cache.get(cache_key)
    # if keys_data is None:
    #     keys_data = requests.get(key_url).text
    #     cache.set(cache_key, keys_data, 3600)

    keys_data = requests.get(key_url).text
    return JWKSet.from_json(keys_data)


def verify_jws(raw_data: str, jwkset: JWKSet) -> dict:
    token = jws.JWS.from_jose_token(raw_data)
    token.verify(jwkset)
    return json.loads(token.payload.decode())


def decrypt_jwe(encrypted_data: str) -> dict:
    jwe_key = jwk.JWK.from_json(myinfo_settings.MYINFO_PRIVATE_KEY_ENC)
    jwetoken = jwe.JWE()
    jwetoken.deserialize(encrypted_data, key=jwe_key)

    # verify the signature of the decrypted JWS
    jwkset = get_jwkset(myinfo_settings.MYINFO_JWKS_DATA_VERIFICATION_URL)
    return verify_jws(jwetoken.payload.decode(), jwkset)
