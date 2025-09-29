import os
import base64
from datetime import date, datetime
from unittest.mock import patch
from contextlib import contextmanager


class MockResponse:
    def __init__(self, status_code=201, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}
    
    def json(self):
        return self._json_data


def mock_get_jwt_token(email: str, password: str,api_key:str):
    mock_jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.mock_signature_for_testing"
    
    response_data = {
        "message": "Login successful",
        "jwt_token": mock_jwt_token
    }
    return MockResponse(status_code=200, json_data=response_data)


def mock_send_api_request(payload: dict, base_url: str, api_key: str, jwt_token: str):
    """Mock implementation of RequestHandler.send_api_request for protect/unprotect operations"""
    
    # Valid data elements
    valid_data_elements = {
        "name", "address", "city", "postcode", "zipcode", "phone", "email", 
        "dob", "nin", "ssn", "ccn", "passport", "iban", "datetime", "number"
    }
    
    # Extract operation type from URL
    operation = "protect" if "/protect" in base_url else "unprotect"
    
    # Validate user
    user = payload.get("user", "")
    if user != "superuser":
        error_response = {
                "error_msg": "3, The user does not have the appropriate permissions to perform the requested operation.",
                "success": False
        }
        return MockResponse(status_code=404, json_data=error_response)
    
    # Validate data element
    data_element = payload.get("data_element", "")
    if data_element not in valid_data_elements:
        error_response = {
                "error_msg": "2, The data element could not be found in the policy.",
                "success": False
        }
        return MockResponse(status_code=404, json_data=error_response)
    
    # Get data and external_iv
    data = payload.get("data", [])
    external_iv = payload.get("external_iv", "")
    encoding = payload.get("encoding", "utf8")
    
    # Character substitution mapping
    char_map_base = {
        'a': 'x', 'b': 'y', 'c': 'z', 'd': 'w', 'e': 'v', 'f': 'u', 'g': 't', 'h': 's',
        'i': 'r', 'j': 'q', 'k': 'p', 'l': 'o', 'm': 'n', 'n': 'm', 'o': 'l', 'p': 'k',
        'q': 'j', 'r': 'i', 's': 'h', 't': 'g', 'u': 'f', 'v': 'e', 'w': 'd', 'x': 'c',
        'y': 'b', 'z': 'a',
        'A': 'X', 'B': 'Y', 'C': 'Z', 'D': 'W', 'E': 'V', 'F': 'U', 'G': 'T', 'H': 'S',
        'I': 'R', 'J': 'Q', 'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L', 'P': 'K',
        'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G', 'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C',
        'Y': 'B', 'Z': 'A',
        '0': '9', '1': '8', '2': '7', '3': '6', '4': '5', '5': '4', '6': '3', '7': '2',
        '8': '1', '9': '0'
    }
    
    # Modify char_map if external_iv is provided
    char_map = char_map_base.copy()
    if external_iv:
        # Simple modification: shift by 1 for external_iv
        for key in char_map:
            if key.isalpha():
                if key.islower():
                    char_map[key] = chr((ord(char_map[key]) - ord('a') + 1) % 26 + ord('a'))
                else:
                    char_map[key] = chr((ord(char_map[key]) - ord('A') + 1) % 26 + ord('A'))
            elif key.isdigit():
                char_map[key] = str((int(char_map[key]) + 1) % 10)
    
    def transform_text(text, is_protect=True):
        """Apply character substitution"""
        if not isinstance(text, str):
            return text
            
        if is_protect:
            # Protect: apply transformation
            return ''.join(char_map.get(c, c) for c in text)
        else:
            # Unprotect: reverse transformation
            reverse_map = {v: k for k, v in char_map.items()}
            return ''.join(reverse_map.get(c, c) for c in text)
    
    def process_data_item(item):
        """Process individual data item based on encoding"""
        if item is None:
            return None
        
        # Special handling for dob data element
        if data_element == "dob":
            # Handle date objects - convert to YYYY-MM-DD format
            if isinstance(item, (date, datetime)):
                if isinstance(item, datetime):
                    item = item.date()
                date_str = item.strftime("%Y-%m-%d")
                if operation == "protect":
                    # For dob, use a simple date transformation that keeps valid YYYY-MM-DD format
                    year, month, day = date_str.split('-')
                    # Simple transformation that maintains valid date ranges
                    new_year = str(int(year) + 1000) if int(year) < 2000 else str(int(year) - 1000)
                    new_month = str(13 - int(month)).zfill(2)
                    new_day = str(32 - int(day)).zfill(2)
                    return f"{new_year}-{new_month}-{new_day}"
                else:
                    # For unprotect, reverse the transformation
                    year, month, day = item.split('-')
                    orig_year = str(int(year) - 1000) if int(year) > 2000 else str(int(year) + 1000)
                    orig_month = str(13 - int(month)).zfill(2)
                    orig_day = str(32 - int(day)).zfill(2)
                    return f"{orig_year}-{orig_month}-{orig_day}"
            elif isinstance(item, str):
                # If it's already a string (protected date), process for unprotect
                if operation == "protect":
                    # Apply date transformation
                    if '-' in item and len(item) == 10:  # YYYY-MM-DD format
                        year, month, day = item.split('-')
                        new_year = str(int(year) + 1000) if int(year) < 2000 else str(int(year) - 1000)
                        new_month = str(13 - int(month)).zfill(2)
                        new_day = str(32 - int(day)).zfill(2)
                        return f"{new_year}-{new_month}-{new_day}"
                    else:
                        return transform_text(item, True)
                else:
                    # Unprotect: reverse date transformation
                    if '-' in item and len(item) == 10:  # YYYY-MM-DD format
                        year, month, day = item.split('-')
                        orig_year = str(int(year) - 1000) if int(year) > 2000 else str(int(year) + 1000)
                        orig_month = str(13 - int(month)).zfill(2)
                        orig_day = str(32 - int(day)).zfill(2)
                        return f"{orig_year}-{orig_month}-{orig_day}"
                    else:
                        return transform_text(item, False)
        
        # Special handling for phone numbers (preserve numeric format)
        if data_element == "phone":
            if isinstance(item, (int, float)):
                # For numeric phone numbers, preserve as numeric
                if operation == "protect":
                    # Simple numeric transformation that preserves digit count
                    return int(str(item)[::-1])  # Reverse digits
                else:
                    # Unprotect: reverse the digits back
                    return int(str(item)[::-1])
            elif isinstance(item, str):
                # String phone numbers use normal transformation
                return transform_text(item, operation == "protect")
        
        # Normal processing for other data elements
        if encoding == "base64":
            # Decode base64, transform, encode back
            try:
                decoded = base64.b64decode(item).decode('utf-8')
                transformed = transform_text(decoded, operation == "protect")
                return base64.b64encode(transformed.encode('utf-8')).decode('utf-8')
            except:
                return item
        else:
            # UTF-8 encoding
            return transform_text(str(item), operation == "protect")
    
    # Process data
    results = []
    for item in data:
        result = process_data_item(item)
        results.append(result)
    
    # Success response
    response_data = {
        "encoding": encoding,
        "results": results,
        "success": True
    }
    
    return MockResponse(status_code=200, json_data=response_data)


@contextmanager
def start_get_jwt_token_mocking():
    with patch('appython.service.auth_token_provider.AuthTokenProvider.get_jwt_token', side_effect=mock_get_jwt_token):
        yield


@contextmanager
def start_protect_unprotect_mocking():
    """Context manager to mock both JWT token and protect/unprotect operations"""
    with patch('appython.service.auth_token_provider.AuthTokenProvider.get_jwt_token', side_effect=mock_get_jwt_token), \
         patch('appython.protector.RequestHandler.send_api_request', side_effect=mock_send_api_request):
        yield
