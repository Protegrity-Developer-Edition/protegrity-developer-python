"""
This module provides the AuthTokenProvider class, which is responsible for authenticating user credentials
and retrieving JWT tokens from the authentication endpoint.
"""

import os
import requests
from appython.utils.constants import HOST as host


class AuthTokenProvider:
    def get_jwt_token(email: str, password: str,api_key:str):
        """
        Authenticate user credentials and retrieve a JWT token.

        This method sends a POST request to the authentication endpoint with the provided
        email and password credentials. Upon successful authentication, it returns the
        server response containing the JWT token and related authentication data.

        Args:
            email (str): User's email address for authentication.
            password (str): User's password for authentication.

        Returns:
            requests.Response: HTTP response object from the authentication request.
                - On success (200): Contains JWT token in response body
                - On failure (401, 403, etc.): Contains error details

        Raises:
            requests.exceptions.RequestException: If the HTTP request fails due to network issues.
            requests.exceptions.ConnectionError: If unable to connect to the authentication server.
            requests.exceptions.Timeout: If the request times out.
        """
        runtime_host = os.getenv('DEV_EDITION_HOST', host)
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
        }
        base_url = f"https://{runtime_host}/auth/login"
        payload = {"email": email, "password": password}
        response = requests.post(base_url, json=payload, headers=headers)
        return response
