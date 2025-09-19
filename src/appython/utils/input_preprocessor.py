"""
This module provides the InputPreprocessor class, which is responsible for validating and processing
input parameters for data protection operations such as PROTECT, UNPROTECT, and REPROTECT.
It ensures that the input data is correctly formatted, handles character sets, and prepares the
parameters for further processing.
"""

from appython.utils.constants import (
    ARGS_PROTECT as args_protect,
    OP_TYPE as op_type,
    ARGS_UNPROTECT as args_unprotect,
    ARGS_REPROTECT as args_reprotect,
    DATATYPES as datatypes,
    ErrorMessage,
    Charset,
)
from appython.utils.codec_helper import (
    convert_b64_bytes_b64_string,
    decode_bytes,
    encode_to_base64_string,
)


def validate_charset(kwargs, response_type):
    """
    Validates the use of the 'charset' keyword argument based on the expected response type.

    This function ensures that the 'charset' parameter is only used when the response type is 'bytes'.
    If 'charset' is provided in the kwargs and the response type is not bytes, an exception is raised.

    Parameters:
        kwargs (dict): Dictionary of keyword arguments that may include 'charset'.
        response_type (type): The expected type of the response (e.g., bytes, str).

    Raises:
        Exception: If 'charset' is specified in kwargs but the response_type is not bytes.
    """

    if "charset" in kwargs and response_type != bytes:
        raise Exception(ErrorMessage.INVALID_CHARSET_TYPE.value)
    else:
        if "charset" in kwargs and response_type == bytes:
            try:
                if kwargs["charset"].value not in [
                    Charset.UTF8.value,
                    Charset.UTF16LE.value,
                    Charset.UTF16BE.value,
                ]:
                    raise Exception(ErrorMessage.UNSUPPORTED_CHARSET.value)
            except Exception:
                raise Exception(ErrorMessage.UNSUPPORTED_CHARSET.value)


class InputPreprocessor:

    @staticmethod
    def validate_parameters(
        kwargs, inp_type, operation_type: str, user: str, de: str, newde: str = None
    ) -> dict:
        """
        Validates and constructs the parameter dictionary for different data protection operations.

        This method ensures that the required parameters for PROTECT, UNPROTECT, and REPROTECT operations
        are present and correctly typed. It also encodes optional parameters like external IVs and tweaks
        into base64 strings when necessary.

        Parameters:
            kwargs (dict): Additional keyword arguments specific to the operation.
            inp_type (type): The expected response type (e.g., str, bytes).
            operation_type (str): The type of operation to perform ('PROTECT', 'UNPROTECT', or 'REPROTECT').
            user (str): The user identifier.
            de (str): The data element name.
            newde (str, optional): The new data element name (required for REPROTECT).

        Returns:
            dict: A dictionary containing validated and formatted parameters for the operation.

        Raises:
            Exception: If any required parameter is missing or of an invalid type, or if unsupported
                        keyword arguments are provided.
        """

        argv = {
            "parameters": {
                "user": user,
                "data_element": de,
                "new_data_element": newde,
                "response_type": inp_type,
            }
        }

        if not isinstance(user, str):
            raise Exception(ErrorMessage.INVALID_USER_NAME.value)

        operation = op_type[operation_type]

        if operation in ["PROTECT", "UNPROTECT"]:

            if de is None or de == "":
                raise Exception(ErrorMessage.DATA_ELEMENT_NONE_EMPTY.value)
            if not isinstance(de, str):
                raise Exception(ErrorMessage.DATA_ELEMENT_NOT_STR.value)

            if "external_iv" in kwargs:
                if not isinstance(kwargs["external_iv"], bytes):
                    raise Exception(
                        ErrorMessage.INVALID_KEYWORD_EXTERNAL_IV.value
                        + f" Expected: bytes, Actual: {type(kwargs['external_iv'])}"
                    )
                argv["parameters"]["external_iv"] = convert_b64_bytes_b64_string(
                    kwargs["external_iv"]
                )

            if "external_tweak" in kwargs:
                if not isinstance(kwargs["external_tweak"], bytes):
                    raise Exception(
                        ErrorMessage.INVALID_KEYWORD_EXTERNAL_TWEAK.value
                        + f" Expected: bytes, Actual: {type(kwargs['external_tweak'])}"
                    )
                argv["parameters"]["external_tweak"] = convert_b64_bytes_b64_string(
                    kwargs["external_tweak"]
                )

            if operation == "PROTECT":
                if "encrypt_to" in kwargs:
                    if kwargs["encrypt_to"] != bytes:
                        raise Exception(
                            ErrorMessage.INVALID_ENC_TYPE.value
                            + f" - {kwargs['encrypt_to']}"
                        )
                    argv["parameters"]["response_type"] = bytes

                validate_charset(kwargs, argv["parameters"]["response_type"])

                for key in kwargs:
                    if key not in args_protect:
                        raise Exception(
                            f"-1, Invalid Keyword Argument: '{key}'. {ErrorMessage.PROTECT_KEYWORD_EXP.value}"
                        )

            elif operation == "UNPROTECT":
                if "decrypt_to" in kwargs:
                    if kwargs["decrypt_to"] not in datatypes:
                        raise Exception(
                            ErrorMessage.INVALID_DEC_TYPE.value
                            + f" - {kwargs['decrypt_to']}"
                        )
                    argv["parameters"]["response_type"] = kwargs["decrypt_to"]

                validate_charset(kwargs, argv["parameters"]["response_type"])

                for key in kwargs:
                    if key not in args_unprotect:
                        raise Exception(
                            f"-1, Invalid Keyword Argument: '{key}'. {ErrorMessage.UNPROTECT_KEYWORD_EXP.value}"
                        )

        elif operation == "REPROTECT":
            if de is None or de == "":
                raise Exception(ErrorMessage.DATA_ELEMENT_NONE_EMPTY.value)
            if not isinstance(de, str):
                raise Exception(ErrorMessage.DATA_ELEMENT_NOT_STR.value)

            if newde is None or newde == "":
                raise Exception(ErrorMessage.NEW_DATA_ELEMENT_NONE_EMPTY.value)
            if not isinstance(newde, str):
                raise Exception(ErrorMessage.NEW_DATA_ELEMENT_NOT_STR.value)

            if "old_external_iv" in kwargs and "new_external_iv" in kwargs:
                if not isinstance(kwargs["old_external_iv"], bytes):
                    raise Exception(
                        ErrorMessage.INVALID_KEYWORD_OLD_EXTERNAL_IV.value
                        + f" Expected: bytes, Actual: {type(kwargs['old_external_iv'])}"
                    )
                argv["parameters"]["old_external_iv_str"] = (
                    convert_b64_bytes_b64_string(kwargs["old_external_iv"])
                )

                if not isinstance(kwargs["new_external_iv"], bytes):
                    raise Exception(
                        ErrorMessage.INVALID_KEYWORD_NEW_EXTERNAL_IV.value
                        + f" Expected: bytes, Actual: {type(kwargs['new_external_iv'])}"
                    )
                argv["parameters"]["new_external_iv"] = convert_b64_bytes_b64_string(
                    kwargs["new_external_iv"]
                )
            elif "old_external_iv" in kwargs or "new_external_iv" in kwargs:
                raise Exception(ErrorMessage.MISSING_OLD_EIV_OR_NEW_EIV.value)

            if "old_external_tweak" in kwargs and "new_external_tweak" in kwargs:
                if not isinstance(kwargs["old_external_tweak"], bytes):
                    raise Exception(
                        ErrorMessage.INVALID_KEYWORD_OLD_EXTERNAL_TWEAK.value
                        + f" Expected: bytes, Actual: {type(kwargs['old_external_tweak'])}"
                    )
                argv["parameters"]["old_external_tweak"] = convert_b64_bytes_b64_string(
                    kwargs["old_external_tweak"]
                )

                if not isinstance(kwargs["new_external_tweak"], bytes):
                    raise Exception(
                        ErrorMessage.INVALID_KEYWORD_NEW_EXTERNAL_TWEAK.value
                        + f" Expected: bytes, Actual: {type(kwargs['new_external_tweak'])}"
                    )
                argv["parameters"]["new_external_tweak"] = convert_b64_bytes_b64_string(
                    kwargs["new_external_tweak"]
                )
            elif "old_external_tweak" in kwargs or "new_external_tweak" in kwargs:
                raise Exception(ErrorMessage.MISSING_OLD_TWEAK_OR_NEW_TWEAK.value)

            if "encrypt_to" in kwargs:
                if kwargs["encrypt_to"] != bytes:
                    raise Exception(
                        ErrorMessage.INVALID_ENC_TYPE.value
                        + f" - {kwargs['encrypt_to']}"
                    )
                argv["parameters"]["response_type"] = bytes

            validate_charset(kwargs, argv["parameters"]["response_type"])

            for key in kwargs:
                if key not in args_reprotect:
                    raise Exception(
                        f"-1, Invalid Keyword Argument: '{key}'. {ErrorMessage.REPROTECT_KEYWORD_EXP.value}"
                    )

        return argv

    @staticmethod
    def convert_input_to_string(
        input_data, kwargs, data_element, operation_type
    ) -> dict:
        """
        Converts input data into a string or base64-encoded format suitable for protection operations.

        This method handles both single and bulk inputs, validates data types, and applies encoding
        or decoding based on the data element and operation type. It also respects character set
        preferences provided in kwargs.

        Parameters:
            input_data (Any): The input data to be processed (can be a single value or a list).
            kwargs (dict): Additional keyword arguments, including optional charset.
            data_element (str): The data element type (used to determine encoding behavior).
            operation_type (str): The operation being performed ('PROTECT', 'UNPROTECT', etc.).

        Returns:
            dict: A dictionary containing the processed data, its type, original data type,
                    charset used, and whether the input was bulk.

        Raises:
            Exception: If the input data contains unsupported or inconsistent types.
        """

        curr_input_datatype = None
        is_bulk = False
        input_type = None
        charset = Charset.UTF8

        if not data_element or not isinstance(data_element, str):
            raise Exception(
                ErrorMessage.DATA_ELEMENT_NONE_EMPTY.value
                if not data_element
                else ErrorMessage.DATA_ELEMENT_NOT_STR.value
            )

        is_enc = "text" in data_element or "BYTE" in data_element

        # Preserve charset from kwargs if valid
        if "charset" in kwargs and isinstance(kwargs["charset"], Charset):
            charset = kwargs["charset"]

        if isinstance(input_data, tuple):
            input_type = type(input_data)
            input_data = list(input_data)
        elif isinstance(input_data, list):
            input_data = input_data.copy()
            input_type = type(input_data)

        if isinstance(input_data, list):
            is_bulk = True
            for index, data in enumerate(input_data):
                if data is None:
                    continue
                type_data = type(data)
                if curr_input_datatype and type_data != curr_input_datatype:
                    raise Exception(ErrorMessage.INVALID_BULK_INPUT.value)
                if type_data in datatypes:
                    curr_input_datatype = curr_input_datatype or type_data
                    if datatypes[type_data] != 5:
                        input_data[index] = (
                            encode_to_base64_string(data)
                            if is_enc and op_type[operation_type] == "PROTECT"
                            else str(data)
                        )
                    else:
                        input_data[index] = decode_bytes(
                            data, charset, is_enc, operation_type
                        )
                else:
                    raise Exception(f"-1, Unsupported input data type {type_data} !")
        else:
            type_data = type(input_data)
            input_type = type_data
            if input_data is not None and type_data in datatypes:
                curr_input_datatype = type_data
                if datatypes[type_data] != 5:
                    input_data = (
                        encode_to_base64_string(input_data)
                        if is_enc and op_type[operation_type] == "PROTECT"
                        else str(input_data)
                    )
                else:
                    input_data = decode_bytes(
                        input_data, charset, is_enc, operation_type
                    )
            elif input_data is not None:
                raise Exception(f"-1, Unsupported input data type {type_data} !")

        return {
            "data": input_data,
            "type": input_type,
            "input_datatype": curr_input_datatype,
            "charset": charset,
            "is_bulk": is_bulk,
        }
