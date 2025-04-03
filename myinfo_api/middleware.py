import logging
import json
import traceback
from django.http import JsonResponse

logger = logging.getLogger(__name__)

class MyInfoExceptionMiddleware:
    """
    Middleware to handle exceptions from the MyInfo API integration.
    This provides consistent error responses across the application.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        """
        Process exceptions and return a standardized JSON response.
        """
        # Log the full exception for debugging
        logger.error(f"Exception in MyInfo API: {str(exception)}")
        logger.error(traceback.format_exc())
        
        # Return a JSON response with error details
        return JsonResponse({
            'error': 'An unexpected error occurred',
            'message': str(exception),
            'type': exception.__class__.__name__
        }, status=500)