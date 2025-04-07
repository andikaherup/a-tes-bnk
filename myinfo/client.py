import base64
import logging
from hashlib import sha256
from json import JSONDecodeError
from urllib.parse import quote, urlencode
from django.utils.crypto import get_random_string

import requests
from myinfo import settings
from myinfo.security import (
    decrypt_jwe,
    generate_client_assertion,
    generate_code_challenge,
    is_valid_code_verifier,
    generate_dpop_header,
    generate_ephemeral_session_keypair,
    get_jwkset,
    verify_jws,
)
from requests import HTTPError

log = logging.getLogger(__name__)


class MyInfoClient(object):
    """
    See API doc at https://public.cloud.myinfo.gov.sg/myinfo/api/myinfo-kyc-v3.1.1.html
    Test data: https://www.ndi-api.gov.sg/library/trusted-data/myinfo/resources-personas.
    """

    API_TIMEOUT = 30
    # MyInfo fields
    context = "com"
    version = "v4"


    def __init__(self, name=None):
        """
        Initialize a request session to interface with remote API
        """
        self.session = requests.Session()

    @classmethod
    def get_url(cls, resource: str):
        """
        Returns the URL for resource.
        """
        return f"{settings.MYINFO_DOMAIN}/{cls.context}/v4/{resource}"
        
    def request(self, api_url, method="GET", extra_headers=None, params=None, data=None):
        """
        Returns:
            dict or str

        Raises:
            requests.RequestException
        """
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }


        if extra_headers:
            headers.update(extra_headers)

        response = self.session.request(
            method,
            url=api_url,
            params=params,
            data=data,
            timeout=self.API_TIMEOUT,
            verify=settings.CERT_VERIFY,
            headers=headers,
        )

        try:
            response.raise_for_status()
        except HTTPError as e:
            print(f"Full error response: {e.response.content if hasattr(e, 'response') else str(e)}")
            raise

        try:
            return response.json()
        except JSONDecodeError:
            return response.text


class MyInfoPersonalClientV4(MyInfoClient):
    """
    See https://public.cloud.myinfo.gov.sg/myinfo/api/myinfo-kyc-v4.0.html
    """
    context = "com"
    version = "v4"
    client_id = settings.MYINFO_CLIENT_ID
    purpose_id = settings.MYINFO_PURPOSE_ID  # Identity verification and credit assessment

    def get_retrieve_resource_url(self, sub: str) -> str:
        return self.get_url("person") + f"/{sub}/"


    @classmethod
    def get_authorise_url(cls, code_verifier: str, callback_url: str) -> str:
        """
        Return a redirect URL to SingPass login page for user's authentication and consent.
        """
        code_challenge = generate_code_challenge(code_verifier)

    
        query = {
            "client_id": cls.client_id,
            "scope": cls.get_scope(),
            "purpose_id": cls.purpose_id,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": callback_url,
        }



        querystring = urlencode(query, safe=",/:", quote_via=quote)
        url = cls.get_url("authorize")
        authorise_url = f"{url}?{querystring}"
        return authorise_url

    @classmethod
    def get_scope(cls):
        """
        Returns the scope string with + instead of spaces
        """
        return settings.MYINFO_SCOPE

    def get_access_token(self, auth_code, code_verifier, callback_url, session_ephemeral_keypair=None):
        """Generate an access token with comprehensive logging and error handling"""
        try:
            api_url = self.get_url("token")
            
            # Validate code verifier
            if not is_valid_code_verifier(code_verifier):
                raise ValueError("Invalid code verifier format")
            
            # Generate ephemeral keypair if not provided
            if session_ephemeral_keypair is None:
                session_ephemeral_keypair = generate_ephemeral_session_keypair()
            
            # Generate client assertion
            jkt_thumbprint = session_ephemeral_keypair.thumbprint()
            client_assertion = generate_client_assertion(api_url, jkt_thumbprint)
            
            # Prepare token request data - use the exact same order as Node.js
            data = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": callback_url,
                "client_id": self.client_id,
                "code_verifier": code_verifier,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion
            }
            
            # Encode data - use standard urlencode without custom handling
            data_encoded = urlencode(data)
            
            # Generate DPoP header
            dpop_header = generate_dpop_header(api_url, session_ephemeral_keypair)

            # Prepare headers - exact format matters
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Cache-Control": "no-cache",
                "DPoP": dpop_header
            }
            


            # Make the token request
            try:
                resp = self.request(
                    api_url,
                    method="POST",
                    extra_headers=headers,
                    data=data_encoded,
                )
                return resp
            except Exception as request_error:
                log.error(f"Token request failed: {str(request_error)}")
                raise
        except Exception as e:
            log.error(f"Error in get_access_token: {str(e)}")
            raise

 
    def get_person_data(self, access_token: str, session_ephemeral_keypair):
        try:
            # Log the start of person data retrieval

        
            # Log JWKS URL being used

        
            # Retrieve JWKS
            try:
                jwkset = get_jwkset(settings.MYINFO_JWKS_TOKEN_VERIFICATION_URL)

            except Exception as jwks_error:
                log.error(f"Error retrieving JWKS: {str(jwks_error)}")
                raise
        
            # Verify access token
            try:
                decoded_access_token = verify_jws(access_token, jwkset)


            except Exception as token_verify_error:
                log.error(f"Error verifying access token: {str(token_verify_error)}")
                raise
        
            # Construct resource URL
            try:
                api_url = self.get_retrieve_resource_url(decoded_access_token["sub"])

            except KeyError as key_error:
                log.error(f"Missing 'sub' in decoded token: {decoded_access_token}")
                raise
        
            # Prepare parameters
            params = {
                "scope": self.get_scope(),
            }

        
            # Generate access token hash for DPoP
            try:
                access_token_hash = sha256(access_token.encode()).digest()
                ath = base64.urlsafe_b64encode(access_token_hash).decode().replace("=", "")

            except Exception as hash_error:
                log.error(f"Error generating access token hash: {str(hash_error)}")
                raise
        
            # Generate DPoP header
            try:
                dpop_header = generate_dpop_header(
                    api_url, session_ephemeral_keypair, method="GET", ath=ath
                )

            except Exception as dpop_error:
                log.error(f"Error generating DPoP header: {str(dpop_error)}")
                raise
        
            # Prepare request headers
            headers = {
                "Authorization": f"DPoP {access_token}",
                "dpop": dpop_header,
                "Cache-Control": "no-cache",
            }

        
            # Make the request
            try:
                resp = self.request(
                    api_url,
                    method="GET",
                    extra_headers=headers,
                    params=params,
                )

                return resp
            except Exception as request_error:
                log.error(f"Error making person data request: {str(request_error)}")
                raise
    
        except Exception as e:
            log.error(f"Unexpected error in get_person_data: {str(e)}")
            raise    

    def retrieve_resource(self, auth_code: str, code_verifier: str, callback_url: str) -> dict:
        session_ephemeral_keypair = generate_ephemeral_session_keypair()
        access_token_resp = self.get_access_token(
            auth_code=auth_code,
            code_verifier=code_verifier,
            callback_url=callback_url,
            session_ephemeral_keypair=session_ephemeral_keypair,
        )
        access_token = access_token_resp["access_token"]
        person_data = self.get_person_data(access_token, session_ephemeral_keypair)

        return decrypt_jwe(person_data)
