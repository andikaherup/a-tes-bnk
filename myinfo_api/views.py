import logging
from django.utils.crypto import get_random_string
from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from myinfo.client import MyInfoPersonalClientV4
from myinfo_api.utils import extract_myinfo_profile
from myinfo.security import generate_code_challenge,generate_code_verifier

logger = logging.getLogger(__name__)

class MyInfoAuthorizeView(APIView):
    """
    View to initiate the MyInfo authorization flow.
    This view generates a state parameter and redirects to MyInfo's authorize page.
    """
    def get(self, request):
        try:
            # Generate a random state for OAuth security
            # oauth_state = get_random_string(length=16)
            
            # Generate a code verifier for PKCE
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier)

            request.session['myinfo_code_verifier'] = code_verifier
            print(f"Generated code verifier: {code_verifier}")
            print(f"Stored in session: {request.session.get('myinfo_code_verifier')}")

            # Get the callback URL from the settings or request query parameters
            callback_url = request.query_params.get(
                'callback_url', 
                request.build_absolute_uri('/callback')
            )
            
            # Store callback URL in session for the callback view
            request.session['myinfo_callback_url'] = callback_url
            
            # Get the authorization URL
            client = MyInfoPersonalClientV4()
            auth_url = client.get_authorise_url(code_challenge, callback_url)
            
            # Redirect user to MyInfo authorization page
            return HttpResponseRedirect(auth_url)
        
        except Exception as e:
            logger.error(f"Error initiating MyInfo authorization: {str(e)}")
            return Response(
                {"error": "Failed to initiate MyInfo authorization"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class MyInfoCallbackView(APIView):
    """
    Callback view for MyInfo to redirect back to after user authorization.
    """
    def get(self, request):
        try:
            # Get the authorization code from the request
            auth_code = request.query_params.get('code')
            
            if not auth_code:
                return Response(
                    {"error": "No authorization code provided"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Retrieve the state and code verifier from session
            # oauth_state = request.session.get('myinfo_oauth_state')
            code_verifier = request.session.get('myinfo_code_verifier')
    
            # When using the verifier in your client

            if not code_verifier:
                logger.error("Invalid or missing code verifier")
                return Response(
                    {"error": "Invalid authentication session"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Retrieve callback URL from session
            callback_url = request.session.get('myinfo_callback_url')
            
            # Exchange the auth code for user data
            client = MyInfoPersonalClientV4()
            person_data = client.retrieve_resource(
                auth_code=auth_code, 
                code_verifier=code_verifier, 
                callback_url=callback_url
            )
            print(f"Person Data: {person_data}")
            # Store the user data in session
            request.session['myinfo_person_data'] = person_data
            
            # Clear the temporary session variables
            # request.session.pop('myinfo_oauth_state', None)
            request.session.pop('myinfo_code_verifier', None)

            
            # Redirect to a frontend route or return the data
            frontend_redirect_url = f"/api/v1/myinfo/profile?status=success"

            return HttpResponseRedirect(frontend_redirect_url)
            
        except Exception as e:
            logger.error(f"Error processing MyInfo callback: {str(e)}")
            
            # Redirect to error page or return error response
            # frontend_error_url = f"/api/v1/myinfo/profile?status=error&message={str(e)}"
            return Response({
            'error': str(e)

        })


class GenerateCodeChallengeView(APIView):
    def post(self, request):
        # Generate a random code verifier
        code_verifier = get_random_string(length=64)
        
        # Store code verifier in session for later use
        request.session['myinfo_code_verifier'] = code_verifier
        
        # Generate code challenge
        code_challenge = generate_code_challenge(code_verifier)
        
        return Response({
            'code_verifier': code_verifier,
            'code_challenge': code_challenge
        })

class MyInfoDataView(APIView):
    """
    View to retrieve previously fetched MyInfo data from the session.
    """
    def get(self, request):
        try:
            # Retrieve the user data from session
            person_data = request.session.get('myinfo_person_data')
            
            if not person_data:
                return Response(
                    {"error": "No MyInfo data found. Please authorize first."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response(person_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error retrieving MyInfo data: {str(e)}")
            return Response(
                {"error": "Failed to retrieve MyInfo data"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class MyInfoProfileView(APIView):
    """
    View to retrieve a simplified profile from MyInfo data.
    """
    def get(self, request):
        try:
            # Retrieve the user data from session
            person_data = request.session.get('myinfo_person_data')
            
            # Check if MyInfo data exists or if this is an initial profile page load
            status_param = request.query_params.get('status')
            if status_param == 'error':
                return Response({
                    "status": "error",
                    "message": request.query_params.get('message', 'Unknown error')
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not person_data:
                return Response({
                    "status": "unauthorized",
                    "message": "No MyInfo data found. Please authorize first."
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Extract and format profile data
            profile = extract_myinfo_profile(person_data)
            
            # Serialize the profile

            
            return Response({
                "status": "success",
                "profile": profile
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error retrieving MyInfo profile: {str(e)}")
            return Response(
                {"status": "error", "message": "Failed to retrieve MyInfo profile"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    

class MyInfoStatusView(APIView):
    """
    View to check if the user is authorized with MyInfo.
    """
    def get(self, request):
        try:
            # Check if MyInfo data exists in session
            person_data = request.session.get('myinfo_person_data')
            
            if person_data and 'uinfin' in person_data and 'value' in person_data['uinfin']:
                return Response({
                    "authorized": True,
                    "user_id": person_data['uinfin']['value']
                }, status=status.HTTP_200_OK)
            
            return Response({
                "authorized": False
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error checking MyInfo status: {str(e)}")
            return Response(
                {"error": "Failed to check MyInfo status"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class MyInfoLogoutView(APIView):
    """
    View to clear MyInfo data from the session.
    """
    def post(self, request):
        try:
            # Remove MyInfo data from session
            request.session.pop('myinfo_person_data', None)
            request.session.pop('myinfo_oauth_state', None)
            request.session.pop('myinfo_code_verifier', None)
            request.session.pop('myinfo_callback_url', None)
            
            return Response({
                "success": True,
                "message": "Successfully logged out from MyInfo"
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error logging out from MyInfo: {str(e)}")
            return Response(
                {"error": "Failed to logout from MyInfo"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )