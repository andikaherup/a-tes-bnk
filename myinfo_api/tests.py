from unittest.mock import patch, MagicMock
from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status
from django.utils.crypto import get_random_string

class MyInfoViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.authorize_url = reverse('myinfo-authorize')
        self.callback_url = reverse('myinfo-callback')
        self.data_url = reverse('myinfo-data')
        
    @patch('myinfo_api.views.MyInfoPersonalClientV4')
    def test_authorize_view(self, mock_myinfo_client):
        # Setup mock
        mock_instance = mock_myinfo_client.return_value
        mock_instance.get_authorise_url.return_value = "https://test.api.myinfo.gov.sg/auth"
        
        # Make request
        response = self.client.get(self.authorize_url)
        
        # Assert redirect
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://test.api.myinfo.gov.sg/auth")
        
    @patch('myinfo_api.views.MyInfoPersonalClientV4')
    def test_callback_view_success(self, mock_myinfo_client):
        # Setup session
        session = self.client.session
        session['myinfo_oauth_state'] = 'test_state'
        session['myinfo_callback_url'] = 'http://testserver/api/v1/myinfo/callback/'
        session.save()
        
        # Setup mock
        mock_instance = mock_myinfo_client.return_value
        mock_person_data = {
            'name': {'value': 'Test User'},
            'uinfin': {'value': 'S1234567A'}
        }
        mock_instance.retrieve_resource.return_value = mock_person_data
        
        # Make request
        response = self.client.get(f"{self.callback_url}?code=test_auth_code")
        
        # Assert response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), mock_person_data)
        
    def test_callback_view_missing_code(self):
        # Make request without code parameter
        response = self.client.get(self.callback_url)
        
        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()['error'], 'No authorization code provided')
        
    def test_callback_view_missing_state(self):
        # Make request without session state
        response = self.client.get(f"{self.callback_url}?code=test_auth_code")
        
        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json()['error'], 'Invalid state parameter')
        
    def test_data_view_no_data(self):
        # Make request without data in session
        response = self.client.get(self.data_url)
        
        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.json()['error'], 'No MyInfo data found. Please authorize first.')
        
    def test_data_view_with_data(self):
        # Setup session with data
        session = self.client.session
        mock_person_data = {
            'name': {'value': 'Test User'},
            'uinfin': {'value': 'S1234567A'}
        }
        session['myinfo_person_data'] = mock_person_data
        session.save()
        
        # Make request
        response = self.client.get(self.data_url)
        
        # Assert response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), mock_person_data)