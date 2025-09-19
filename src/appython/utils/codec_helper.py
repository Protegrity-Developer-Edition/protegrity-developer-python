"""
This module provides helper functions for encoding and decoding data, particularly focusing on
base64 transformations and character set handling. It includes functions to convert between byte
strings and base64-encoded strings, as well as functions to decode byte data based on specified
character sets and operation types.
"""

import base64
from appython.utils.constants import Charset, OP_TYPE as op_type


def convert_b64_bytes_b64_string(data: bytes) -> str:
    """
    Encodes a byte string into a base64-encoded UTF-8 string.

    Parameters:
        data (bytes): The input byte data to encode.

    Returns:
        str: A base64-encoded string representation of the input bytes.
    """
    return base64.b64encode(data).decode("utf-8")


def convert_bytes_b64_string(data: bytes, charset: str) -> str:
    """
    Encodes byte data into a base64 string and re-encodes it using the specified character set.

    Parameters:
        data (bytes): The input byte data to encode.
        charset (str): The character set to use for encoding the base64 string.

    Returns:
        str: A base64-encoded string re-encoded using the specified charset.
    """
    return base64.b64encode(data).decode("ascii").encode(charset).decode(charset)


def decode_bytes(data: bytes, charset: Charset, is_enc: bool, operation: str) -> str:
    """
    Decodes byte data into a string, optionally applying base64 decoding based on the operation type.

    Parameters:
        data (bytes): The byte data to decode.
        charset (Charset): The character set to use for decoding.
        is_enc (bool): Indicates whether the data is base64-encoded.
        operation (str): The operation type (e.g., 'PROTECT', 'UNPROTECT', 'REPROTECT').

    Returns:
        str: The decoded string.

    Raises:
        Exception: If the operation type is unsupported.
    """

    if not is_enc:
        return data.decode(charset.name.lower())
    if op_type[operation] in ["UNPROTECT", "REPROTECT"]:
        return convert_b64_bytes_b64_string(data)
    return convert_bytes_b64_string(data, charset.name.lower())


def encode_to_base64_string(data) -> str:
    """
    Converts any input data to a UTF-8 base64-encoded string.

    Parameters:
        data: The input data to encode (typically str, int, float, etc.).

    Returns:
        str: A base64-encoded UTF-8 string representation of the input.
    """
    return base64.b64encode(str(data).encode("utf-8")).decode("utf-8")


def get_str_from_b64(data: str):
    """
    Decodes a base64-encoded UTF-8 string back to its original string form.

    Parameters:
        data (str): The base64-encoded string.

    Returns:
        str: The decoded original string.
    """
    return base64.b64decode(data.encode("utf-8")).decode("utf-8")
