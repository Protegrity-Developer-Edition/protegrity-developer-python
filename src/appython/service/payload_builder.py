"""
This module provides the PayloadBuilder class, which constructs the payload for API requests
based on the operation type (PROTECT, UNPROTECT, REPROTECT).
"""
import os
from appython.utils.constants import (
    ErrorMessage, 
    OP_TYPE as op_type,
    HOST as host,
    VERSION as version,
    LOG_RETURN_CODE_UNSUPPORTED as log_return_code
)

def get_base_url(operation_type: str) -> str:
    """
    Constructs the base URL for the API endpoint based on the operation type.

    Parameters:
        operation_type (str): The type of operation (e.g., 'PROTECT', 'UNPROTECT', 'REPROTECT').

    Returns:
        str: The constructed base URL for the API call.
    """
    runtime_host = os.getenv('DEV_EDITION_HOST', host)
    runtime_version = os.getenv('DEV_EDITION_VERSION', version)

    return f"https://{runtime_host}/v{runtime_version}/{operation_type}"


class PayloadBuilder:
    def build_api_request(input: dict, arguments: dict, operation_type: str):
        """
        Builds the API request payload and return type metadata for a given data protection operation.

        This method constructs a structured payload for the PROTECT, UNPROTECT, or REPROTECT operations,
        including user info, data, data elements, encoding type, and optional IVs or tweaks. It also prepares
        a return type template that describes how the response should be interpreted.

        Parameters:
            input (dict): Contains the input data, its type, charset, and whether it's bulk.
            arguments (dict): Contains operation parameters such as user, data element, response type, and optional IVs.
            operation_type (str): The type of operation being performed ('PROTECT', 'UNPROTECT', or 'REPROTECT').

        Returns:
            tuple: A tuple containing:
                - payload_template (dict): The structured payload for the API request.
                - return_type_template (dict): Metadata describing how to interpret the API response.
                - url (str): The full API endpoint URL for the operation.

        Raises:
            Exception: If required parameters are missing, types are invalid, or unsupported operation types are used.
        """

        payload_template = {
            "user": None,
            "encoding": "utf8",
            "data_element": None,
            "data": [],
            "external_iv": None,
        }

        return_type_template = {
            "is_bulk": None,
            "response_type": None,
            "type": None,
            "charset": None,
            "isENC": False,
        }

        parameters = arguments["parameters"]
        data_element = parameters["data_element"]
        response_type = parameters["response_type"]
 
        if "ENC" in data_element:
            if op_type[operation_type] in ("PROTECT", "REPROTECT"):
                if response_type != bytes:
                    raise Exception(f"26, {log_return_code[26]}")
            else:
                if input["input_datatype"] != bytes:
                    raise Exception(f"26, {log_return_code[26]}")

        if "text" in data_element or "BYTE" in data_element:
            return_type_template["isENC"] = True
            payload_template["encoding"] = "base64"

        if op_type[operation_type] in ("PROTECT", "UNPROTECT"):
            payload_template["user"] = parameters["user"]
            payload_template["data_element"] = data_element

            if input["is_bulk"] is False:
                payload_template["data"].append(input["data"])
            elif input["is_bulk"] is True:
                payload_template["data"] = input["data"]
            else:
                raise Exception(ErrorMessage.ERROR_SETTING_DATA.value)

            return_type_template["type"] = input["type"]

            if "external_iv" in parameters:
                payload_template["external_iv"] = parameters["external_iv"]

        elif op_type[operation_type] == "REPROTECT":
            payload_template["user"] = parameters["user"]
            payload_template["old_data_element"] = data_element
            payload_template["data_element"] = parameters[
                "new_data_element"
            ]

            if input["is_bulk"] is False:
                payload_template["data"].append(input["data"])
            elif input["is_bulk"] is True:
                payload_template["data"] = input["data"]
            else:
                raise Exception(ErrorMessage.ERROR_SETTING_DATA.value)

            return_type_template["type"] = input["type"]

            if "old_external_iv_str" in parameters:
                payload_template["old_external_iv"] = parameters[
                    "old_external_iv_str"
                ]
            if "new_external_iv" in parameters:
                payload_template["external_iv"] = parameters[
                    "new_external_iv"
                ]
        else:
            raise Exception(ErrorMessage.UNSUPPORTED_OPS_TYPE.value)

        return_type_template["is_bulk"] = input["is_bulk"]
        return_type_template["response_type"] = response_type
        return_type_template["charset"] = input["charset"]

        return payload_template, return_type_template, get_base_url(operation_type)
