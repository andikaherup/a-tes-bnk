import logging
from django.shortcuts import redirect
from django.utils.crypto import get_random_string
from django.http import HttpResponseRedirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from myinfo.client import MyInfoPersonalClientV4
from django.conf import settings
from .utils import extract_myinfo_profile
from .serializers import MyInfoProfileSerializer

logger = logging.getLogger(__name__)

class MyInfoAuthorizeView(APIView):
    """
    View to initiate the MyInfo authorization flow.
    This view generates a state parameter and redirects to MyInfo's authorize page.
    """
    def get(self, request):
        try:
            # Generate a random state for OAuth security
            oauth_state = get_random_string(length=16)
            
            # Store the state in the session for later verification
            request.session['myinfo_oauth_state'] = oauth_state
            
            # Get the callback URL from the settings or request query parameters
            callback_url = request.query_params.get(
                'callback_url', 
                request.build_absolute_uri('/api/v1/myinfo/callback/')
            )
            
            # Store callback URL in session for the callback view
            request.session['myinfo_callback_url'] = callback_url
            
            # Get the authorization URL
            client = MyInfoPersonalClientV4()
            auth_url = client.get_authorise_url(oauth_state, callback_url)
            
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
    This view processes the auth code from MyInfo and retrieves user data.
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
            
            # Retrieve the state from session
            oauth_state = request.session.get('myinfo_oauth_state')
            
            if not oauth_state:
                return Response(
                    {"error": "Invalid state parameter"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Retrieve callback URL from session
            callback_url = request.session.get('myinfo_callback_url')
            
            # Exchange the auth code for user data
            client = MyInfoPersonalClientV4()
            person_data = client.retrieve_resource(auth_code, oauth_state, callback_url)
            
            # Clear session data after use
            request.session.pop('myinfo_oauth_state', None)
            request.session.pop('myinfo_callback_url', None)
            
            # Store the user data in session or return it directly
            request.session['myinfo_person_data'] = person_data
            
            # Redirect to the frontend success page if provided
            success_url = request.query_params.get('success_url')
            if success_url:
                return HttpResponseRedirect(success_url)
            
            # Return the retrieved data
            return Response(person_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error processing MyInfo callback: {str(e)}")
            return Response(
                {"error": "Failed to process MyInfo callback", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MyInfoCallbackView(APIView):
    """
    Callback view for MyInfo to redirect back to after user authorization.
    This view processes the auth code from MyInfo and retrieves user data.
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
            
            # Retrieve the state from session
            oauth_state = request.session.get('myinfo_oauth_state')
            
            if not oauth_state:
                return Response(
                    {"error": "Invalid state parameter"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Retrieve callback URL from session
            callback_url = request.session.get('myinfo_callback_url')
            
            # Exchange the auth code for user data
            client = MyInfoPersonalClientV4()
            person_data = client.retrieve_resource(auth_code, oauth_state, callback_url)
            
            # Clear session data after use
            request.session.pop('myinfo_oauth_state', None)
            request.session.pop('myinfo_callback_url', None)
            
            # Store the user data in session or return it directly
            request.session['myinfo_person_data'] = person_data
            
            # Redirect to the frontend success page if provided
            success_url = request.query_params.get('success_url')
            if success_url:
                return HttpResponseRedirect(success_url)
            
            # Return the retrieved data
            return Response(person_data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error processing MyInfo callback: {str(e)}")
            return Response(
                {"error": "Failed to process MyInfo callback", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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
            
            if not person_data:
                return Response(
                    {"error": "No MyInfo data found. Please authorize first."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Extract and format profile data
            profile = extract_myinfo_profile(person_data)
            
            # Serialize the profile
            serializer = MyInfoProfileSerializer(profile)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error retrieving MyInfo profile: {str(e)}")
            return Response(
                {"error": "Failed to retrieve MyInfo profile"},
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