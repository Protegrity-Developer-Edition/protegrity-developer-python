"""
This module provides the RequestHandler class, which is responsible for sending HTTP requests to a specified API
endpoint using the `requests` library. It includes methods to send POST requests with JSON payloads and handle
the necessary headers for authentication.
"""

import requests


class RequestHandler:
    def send_api_request(
        payload: dict, base_url: str, api_key: str, jwt_token: str
    ) -> requests.Response:
        """
        Sends a POST request to the specified API endpoint with a JSON payload.

        This method uses the `requests` library to send a POST request to the given `base_url`,
        including the provided `payload` as JSON and setting the appropriate content-type header.

        Parameters:
            payload (dict): The JSON-serializable payload to send in the request body.
            base_url (str): The full URL of the API endpoint to which the request is sent.

        Returns:
            Response: The HTTP response object returned by the `requests.post` call.
        """
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "Authorization": jwt_token,
        }
        response = requests.post(base_url, json=payload, headers=headers)
        return response
