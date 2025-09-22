"""
This module contains all the exceptions raised by AP Python.
"""

import re
from appython.utils.constants import ERROR_MAPPING as error_mapping


class PythonSDKException:
    """Base exception for all AP Python SDK errors."""

    @staticmethod
    def map_error_message(error_msg: str) -> str:
        """
        Map error message to standardized format using regex patterns to extract the actual error message.

        This function processes error messages from API responses by:
        1. Using regex patterns to identify and extract the core error message
        2. Looking up the extracted message in the error_mapping dictionary
        3. Returning the mapped error code and description, or the original message if not found

        Supported patterns:
        - "(*) failed. IP:Message" -> extracts "Message"
        - "(*) failed. Message" -> extracts "Message"
        - "Message" -> extracts "Message" (direct message)

        Args:
            error_msg (str): Original error message from the operation response.
                            Examples:
                            - "Unprotect failed. 169.254.17.189:The content of the input data is not valid."
                            - "Protect failed. Invalid email address"
                            - "(*) failed. Something:Error message"
                            - "The content of the input data is not valid."

        Returns:
            str: Mapped error message in "code, description" format if found in mapping,
                otherwise returns the original error message unchanged.

        Examples:
            >>> map_error_message("Unprotect failed. 169.254.17.189:The content of the input data is not valid.")
            "44, The content of the input data is not valid."

            >>> map_error_message("Protect failed. Invalid email address")
            "44, The content of the input data is not valid."

            >>> map_error_message("The content of the input data is not valid.")
            "44, The content of the input data is not valid."
        """
        if not error_msg:
            return error_msg

        # Define regex patterns to extract the actual error message
        patterns = [
            # Pattern 1: "Anything failed. IP/Server:Message" -> extract "Message"
            r'.*\s+failed\.\s+[^:]+:(.+)$',
            
            # Pattern 2: "Anything failed. Message" -> extract "Message" 
            r'.*\s+failed\.\s+(.+)$',
            
            # Pattern 3: Direct message (no "failed" prefix) -> extract whole message
            r'^(.+)$'
        ]

        extracted_message = None
        
        # Try each pattern until we find a match
        for pattern in patterns:
            match = re.match(pattern, error_msg.strip(), re.IGNORECASE)
            if match:
                extracted_message = match.group(1).strip()
                break
        
        # If no pattern matched, use the original message
        if not extracted_message:
            extracted_message = error_msg

        # Look up the extracted message in error_mapping dictionary
        if extracted_message in error_mapping:
            return error_mapping[extracted_message]

        # Try partial matching for cases where the extracted message might have extra content
        for key in error_mapping:
            if extracted_message.startswith(key):
                return error_mapping[key]
            # Also try reverse - if the key starts with our extracted message
            if key.startswith(extracted_message):
                return error_mapping[key]

        # If no match found, return original message
        return error_msg


class ProtectorError(Exception):
    """An error occurred during the tokenization or encryption operation."""

    def __init__(self, wrapped_exc=None, err_msg=None):
        """Initialize Protector error with appropriate exception or error msg.

        Args:
            wrapped_exc (PepProviderError): Exception containing error code
                and message.
            err_msg (str): Exception message.
        """
        if wrapped_exc is not None:
            msg = wrapped_exc.err_msg
            code = wrapped_exc.err_code
            if code is not None:
                msg = "%s, %s" % (str(code), wrapped_exc.err_msg)
        else:
            msg = err_msg
        super(ProtectorError, self).__init__(msg)


class InitializationError(ProtectorError):
    """Protector object could not be initialized.

    This could be due to one of the following reasons:
    - Pepserver is down
    - Application calling AP Python is not trusted one
    - Native module is missing
    """


class ProtectError(ProtectorError):
    """A Protect operation failed."""


class UnprotectError(ProtectorError):
    """An Un-protect operation failed."""


class ReprotectError(ProtectorError):
    """A Re-protec operation failed."""


class InvalidSessionError(ProtectorError):
    """Session used for the protection operation is invalid.

    This could be due to invalid parameters passed while creating session.
    Or if a session has timed out.
    """
