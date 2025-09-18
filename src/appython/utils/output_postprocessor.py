"""
This module provides the OutputProcessor class, which is responsible for restoring the original data types
of protected or transformed values based on specified metadata. It supports various data types including
strings, integers, floats, bytes with specific charsets, and dates in multiple formats.
"""

import base64
from datetime import date, datetime
from appython.utils.constants import (
    Charset,
    LOG_RETURN_CODE_UNSUPPORTED as log_return_code
) 
from appython.utils.codec_helper import get_str_from_b64


class OutputProcessor:
    @staticmethod
    def restore_original_type(data: list, return_type: dict):
        """
        Restores the original data type(s) of protected or transformed values based on the specified return metadata.

        This method decodes or converts each item in the input list `data` to its intended type as described in
        the `return_type` dictionary. It supports both single and bulk inputs, and handles decoding for base64-encoded
        strings, numeric types, byte strings with specific charsets, and date formats.

        Parameters:
            data (list): A list of values (usually strings) to be converted back to their original types.
            return_type (dict): Metadata describing the expected output format. Keys include:
                - "is_bulk" (bool): Whether the input is a list of values or a single value.
                - "response_type" (type): The target Python type (e.g., str, int, float, bytes, date).
                - "isENC" (bool): Whether the input values are base64-encoded.
                - "charset" (Charset, optional): Character encoding to use when decoding byte strings.

        Returns:
            The decoded value(s), either as a single item or a list, depending on the `is_bulk` flag.

        Raises:
            Exception: If decoding fails or the response type is unsupported.
        """
        try:
            is_bulk = return_type["is_bulk"]
            response_type = return_type["response_type"]
            is_enc = return_type["isENC"]
            charset = return_type.get("charset")

            def decode(item):
                if item is None:
                    return None
                if response_type == str:
                    return get_str_from_b64(item) if is_enc else item
                elif response_type == int:
                    return int(get_str_from_b64(item)) if is_enc else int(item)
                elif response_type == float:
                    return float(get_str_from_b64(item)) if is_enc else float(item)
                elif response_type == bytes:
                    if is_enc:
                        return base64.b64decode(item)
                    if charset.value == Charset.UTF8.value:
                        return item.encode("utf-8")
                    elif charset.value == Charset.UTF16LE.value:
                        return item.encode("utf-16le")
                    elif charset.value == Charset.UTF16BE.value:
                        return item.encode("utf-16be")
                elif response_type == date:
                    date_formats = [
                        "%Y-%m-%d",  # 2023-12-25
                        "%Y/%m/%d",  # 2023/12/25
                        "%Y/%d/%m",  # 2023/25/12
                        "%m/%d/%Y",  # 12/25/2023
                        "%d/%m/%Y",  # 25/12/2023
                        "%m-%d-%Y",  # 12-25-2023
                        "%d-%m-%Y",  # 25-12-2023
                        "%Y%m%d",  # 20231225
                        "%d.%m.%Y",  # 25.12.2023
                        "%Y.%m.%d",  # 2023.12.25
                    ]

                    for fmt in date_formats:
                        try:
                            return datetime.strptime(item, fmt).date()
                        except ValueError:
                            continue

                    # If no format worked, raise an error with the original item
                    raise ValueError(
                        f"Unable to parse date format for: '{item}'. Supported formats: {date_formats}"
                    )
                elif response_type == type(None):
                    return None
                else:
                    raise Exception(f"26, {log_return_code[26]}")

            if not is_bulk:
                return decode(data[0])
            else:
                return [decode(item) for item in data]

        except Exception:
            raise Exception(f"26, {log_return_code[26]}")
