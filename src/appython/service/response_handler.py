"""
This module provides the ResponseHandler class, which processes HTTP responses from the API.
"""

from appython.utils.output_postprocessor import OutputProcessor
from appython.utils.constants import (
    RETURN_CODE as return_code,
    LOG_RETURN_CODE_UNSUPPORTED as log_return_code
)
from appython.utils.exceptions import PythonSDKException


class ResponseHandler:
    @staticmethod
    def process(response, return_type: dict, operation_type: str):
        """
        Processes the HTTP response from the API and restores the original data type(s) of the result.

        This method handles both successful and error responses. For successful responses (HTTP 200),
        it checks the return code inside the response payload and uses the OutputProcessor to convert
        the returned data into its original type(s) based on the `return_type` metadata.

        Parameters:
            response (requests.Response): The HTTP response object returned by the API call.
            return_type (dict): Metadata describing how to interpret the response data. Keys include:
                - "is_bulk" (bool): Whether the response contains a list of values.
                - "response_type" (type): The expected type of the response values.
                - "type" (type): The container type for the result (e.g., list, tuple).
                - "isENC" (bool): Whether the data is base64-encoded.
                - "charset" (Charset, optional): Character encoding used for decoding bytes.

        Returns:
            The processed result, either as a single value or a collection (list or tuple),
            along with a tuple of return codes if bulk.

        Raises:
            Exception: If the return code indicates failure, if the response is malformed,
                        or if the data cannot be decoded or restored properly.
        """
        if response.status_code == 200:
            response_json = response.json()
            is_query_success = response_json.get("success")

            if not is_query_success:
                try:
                    message = response.json().get("error_msg", "Unknown Error")
                    mapped_message = PythonSDKException.map_error_message(message)
                except Exception:
                    mapped_message = "Failed to parse error message from response"
                raise Exception(mapped_message)

            data = response_json.get("results")
            try:
                result = OutputProcessor.restore_original_type(data, return_type)

                if not return_type.get("is_bulk", False):
                    return result
                else:
                    return_type_cls = return_type.get("type", list)
                    if return_type_cls == tuple:
                        return tuple(result), (return_code[operation_type],) * len(data)
                    else:
                        return result, (return_code[operation_type],) * len(data)
            except Exception:
                raise Exception(f"26, {log_return_code[26]}")  # Error in setting data
        else:
            is_query_success = response.json().get("success", "Unknown Error")
            if not is_query_success:
                try:
                    message = response.json().get("error_msg", "Unknown Error")
                    mapped_message = PythonSDKException.map_error_message(message)
                except Exception:
                    mapped_message = "Failed to parse error message from response"
                raise Exception(mapped_message)
            if response.status_code == 403:
                message = response.json().get("message", "Forbidden")
                raise Exception(message)

