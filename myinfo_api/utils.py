import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Custom exception handler for REST Framework that provides
    standardized error responses across the application.
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    # If the response is None, this is an unhandled exception
    if response is None:

        return Response(
            {
                'error': 'An unexpected error occurred',
                'message': str(exc),
                'type': exc.__class__.__name__
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # Return the modified response with standardized format
    return response

def extract_myinfo_profile(person_data):
    """
    Extract common profile information from MyInfo person data and return a simplified profile.
    This is useful for applications that only need basic user information.
    
    Args:
        person_data (dict): The full person data from MyInfo
        
    Returns:
        dict: A simplified user profile with common fields
    """
    profile = {}
    
    # Extract basic information
    if 'uinfin' in person_data and 'value' in person_data['uinfin']:
        profile['id'] = person_data['uinfin']['value']
    
    if 'name' in person_data and 'value' in person_data['name']:
        profile['name'] = person_data['name']['value']
    
    if 'email' in person_data and 'value' in person_data['email']:
        profile['email'] = person_data['email']['value']
    
    # Extract mobile number
    if 'mobileno' in person_data and 'nbr' in person_data['mobileno']:
        prefix = person_data['mobileno'].get('prefix', {}).get('value', '')
        areacode = person_data['mobileno'].get('areacode', {}).get('value', '')
        number = person_data['mobileno'].get('nbr', {}).get('value', '')
        profile['mobile'] = f"{prefix}{areacode}{number}"
    
    # Extract address
    if 'regadd' in person_data:
        address_parts = []
        regadd = person_data['regadd']
        
        block = regadd.get('block', {}).get('value', '')
        if block:
            address_parts.append(f"Block {block}")
        
        floor = regadd.get('floor', {}).get('value', '')
        unit = regadd.get('unit', {}).get('value', '')
        if floor and unit:
            address_parts.append(f"#{floor}-{unit}")
        
        building = regadd.get('building', {}).get('value', '')
        if building:
            address_parts.append(building)
        
        street = regadd.get('street', {}).get('value', '')
        if street:
            address_parts.append(street)
        
        postal = regadd.get('postal', {}).get('value', '')
        if postal:
            address_parts.append(f"Singapore {postal}")
        
        profile['address'] = ', '.join(filter(None, address_parts))
    
    # Add demographic information
    if 'dob' in person_data and 'value' in person_data['dob']:
        profile['dob'] = person_data['dob']['value']
    
    if 'sex' in person_data and 'desc' in person_data['sex']:
        profile['gender'] = person_data['sex']['desc']
    
    if 'nationality' in person_data and 'desc' in person_data['nationality']:
        profile['nationality'] = person_data['nationality']['desc']
    
    if 'residentialstatus' in person_data and 'desc' in person_data['residentialstatus']:
        profile['residentialstatus'] = person_data['residentialstatus']['desc']
    
    if 'marital' in person_data and 'desc' in person_data['marital']:
        profile['maritalstatus'] = person_data['marital']['desc']
    
    return profile