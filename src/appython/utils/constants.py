"""
This module defines constants and enumerations used throughout the application,
including data types, operation types, argument mappings, character sets, access types,
and standardized error messages.
"""

from datetime import date
from enum import Enum

DATATYPES = {
    str: 1,
    int: 2,
    float: 3,
    date: 4,
    bytes: 5,
}

HOST = "api.developer-edition.protegrity.com"
VERSION = "1"

OP_TYPE = {"protect": "PROTECT", "unprotect": "UNPROTECT", "reprotect": "REPROTECT"}

RETURN_CODE = {"protect": 6, "unprotect": 8, "reprotect": 50}

ARGS_PROTECT = {"external_iv": 1, "external_tweak": 2, "encrypt_to": 3, "charset": 4}

ARGS_UNPROTECT = {"external_iv": 1, "external_tweak": 2, "decrypt_to": 3, "charset": 4}

ARGS_REPROTECT = {
    "old_external_iv": 1,
    "new_external_iv": 2,
    "old_external_tweak": 3,
    "new_external_tweak": 4,
    "encrypt_to": 5,
    "charset": 6,
}


class Charset(Enum):
    UTF8 = 2
    UTF16LE = 4
    UTF16BE = 5


class CheckAccessType(Enum):
    PROTECT = 6
    UNPROTECT = 7
    REPROTECT = 8


class ErrorMessage(Enum):
    DATA_ELEMENT_NONE_EMPTY = "-1, Data element cannot be none or empty"
    DATA_ELEMENT_NOT_STR = "-1, Data element parameter should be of String type."
    NEW_DATA_ELEMENT_NONE_EMPTY = "-1, New Data element cannot be none or empty"
    NEW_DATA_ELEMENT_NOT_STR = (
        "-1, New Data element parameter should be of String type."
    )
    INVALID_KEYWORD_EXTERNAL_IV = "-1, Invalid Keyword Type for keyword: external_iv!!"
    INVALID_KEYWORD_EXTERNAL_TWEAK = (
        "-1, Invalid Keyword Type for keyword: external_tweak!!"
    )
    INVALID_KEYWORD_OLD_EXTERNAL_IV = (
        "-1, Invalid Keyword Type for keyword: old_external_iv!!"
    )
    INVALID_KEYWORD_NEW_EXTERNAL_IV = (
        "-1, Invalid Keyword Type for keyword: new_external_iv!!"
    )
    INVALID_KEYWORD_OLD_EXTERNAL_TWEAK = (
        "-1, Invalid Keyword Type for keyword: old_external_tweak!!"
    )
    INVALID_KEYWORD_NEW_EXTERNAL_TWEAK = (
        "-1, Invalid Keyword Type for keyword: new_external_tweak!!"
    )
    MISSING_OLD_EIV_OR_NEW_EIV = "-1, old_external_iv and new_external_iv both are required for reprotect operation !"
    MISSING_OLD_TWEAK_OR_NEW_TWEAK = "-1, old_external_tweak and new_external_tweak both are required for reprotect operation !"
    INVALID_ENC_TYPE = "-1, Invalid encryption output type!"
    INVALID_DEC_TYPE = "-1, Invalid decryption output type!"
    INVALID_CHARSET_TYPE = "-1, Charset is only supported with byte input data type"
    PROTECT_KEYWORD_EXP = "Expecting one of these: ['external_iv', 'external_tweak', 'charset', 'int_size', 'encrypt_to']"
    UNPROTECT_KEYWORD_EXP = "Expecting one of these: ['external_iv', 'external_tweak', 'charset', 'int_size', 'decrypt_to']"
    REPROTECT_KEYWORD_EXP = "Expecting one of these: ['old_external_iv', 'new_external_iv','old_external_tweak', 'new_external_tweak', 'charset', 'int_size', 'encrypt_to']"
    INVALID_BULK_INPUT = "-1, Bulk input data cannot have different data types!"
    UNSUPPORTED_CHARSET = "-1, Unsupported Charset Passed.Use the Charset enum to pass utf-8,utf-16le or utf-16be charset!"
    INVALID_USER_NAME = "-1, User name parameter should be of String type."
    ERROR_SETTING_DATA = "-1, Could not set data !"
    ERROR_SETTING_OUT_DATA = "-1, Could not set output !"
    UNSUPPORTED_OPS_TYPE = "-1,Operation type received is invalid!"


LOG_RETURN_CODE_SUCCESS = {
    6: "Data protection was successful.",
    8: "Data unprotect operation was successful.",
    50: "Data reprotect operation was successful.",
}

LOG_RETURN_CODE_UNSUPPORTED = {
    26: "Unsupported algorithm or unsupported action for the specific data element."
}

_ERR_INTERNAL = "13, Internal error occurring in a function call after the Core Provider has been opened."
_ERR_INVALID_CONTENT = "44, The content of the input data is not valid."
_ERR_INPUT_LIMITS = "12, Input is null or not within allowed limits."
_ERR_UNSUPPORTED_ACTION = "26, Unsupported algorithm or unsupported action for the specific data element."
_ERR_DATA_TOO_LONG = "23, Data is too long to be protected/unprotected."
_ERR_BUFFER_TOO_SMALL = "21, Input or output buffer is too small."
_ERR_PERMISSION_ONLY = (
    "10, The user has the appropriate permissions to perform the requested operation. "
    "This is just a policy check and no data has been protected nor unprotected."
)
_ERR_UNPROTECT_FAILED = "9, Data unprotect operation failed."
_ERR_DE_NOT_FOUND = "2, The data element could not be found in the policy."

ERROR_MAPPING = {
    "Access Key security groups not found": "ACCESSKEY_NOT_FOUND",
    "Alphabet was not found": _ERR_INTERNAL,
    "Application has been authorized.": "27, Application has been authorized.",
    "Application has not been authorized.": "28, Application has not been authorized.",
    "Bulk re-protect is not supported": "51, Failed to send logs, connection refused !",
    "Card type must be invalid input": _ERR_INVALID_CONTENT,
    "Card type must be valid input": _ERR_INVALID_CONTENT,
    "Create operation failed.": "35, Create operation failed.",
    "Create operation was successful.": "34, Create operation was successful.",
    "Crypto operation failed": _ERR_INTERNAL,
    "Data is too long to be protected/unprotected": _ERR_DATA_TOO_LONG,
    "Data is too long to be protected/unprotected.": _ERR_DATA_TOO_LONG,
    "Data is too short to be protected/unprotected.": "22, Data is too short to be protected/unprotected.",
    "Data protect operation failed.": "7, Data protection failed.",
    "Data protect operation was successful.": "6, Data protection was successful.",
    "Data reprotect operation was successful.": "50, Data protection was successful.",
    "Data unprotect operation failed.": _ERR_UNPROTECT_FAILED,
    "Data unprotect operation was successful with use of an inactive keyid.": "11, Data unprotect operation was successful with use of an inactive keyid.",
    "Data unprotect operation was successful.": "8, Data unprotect operation was successful.",
    "Delete operation failed.": "33, Delete operation failed.",
    "Delete operation was successful.": "32, Delete operation was successful.",
    "Encoding must be provided": _ERR_INPUT_LIMITS,
    "Encoding not supported": "UNSUPPORTED_ENCODING",
    "External IV is not supported in this version": "16, External IV is not supported in this version.",
    "FPE value identification position is bigger than the data": _ERR_INPUT_LIMITS,
    "FPE value identification position is invalid": _ERR_INVALID_CONTENT,
    "Failed to acquire policy mutex": "17, Failed to initialize the PEP - This is a fatal error",
    "Failed to allocate memory.": "20, Failed to allocate memory.",
    "Failed to calculate policy hash": _ERR_INTERNAL,
    "Failed to check for first call": _ERR_INTERNAL,
    "Failed to clear key context": _ERR_PERMISSION_ONLY,
    "Failed to convert input data": _ERR_BUFFER_TOO_SMALL,
    "Failed to convert output data": _ERR_INTERNAL,
    "Failed to convert padded input data": _ERR_INTERNAL,
    "Failed to create Alphabet mutex": _ERR_INTERNAL,
    "Failed to create event for flush thread": _ERR_INTERNAL,
    "Failed to create key context": _ERR_PERMISSION_ONLY,
    "Failed to create log mutex": _ERR_INTERNAL,
    "Failed to create policy Mutex": _ERR_INTERNAL,
    "Failed to get binary alphabet": _ERR_BUFFER_TOO_SMALL,
    "Failed to get session from cache": _ERR_INTERNAL,
    "Failed to initialize crypto library": _ERR_INTERNAL,
    "Failed to initialize the PEP - This is a fatal error": "17, Failed to initialize the PEP - This is a fatal error",
    "Failed to load Alphabet from Shmem": _ERR_INTERNAL,
    "Failed to load FPE Properties from Shmem": _ERR_INTERNAL,
    "Failed to load FPE prop - Internal error": _ERR_INTERNAL,
    "Failed to load FPE prop - No such element": _ERR_INTERNAL,
    "Failed to load data encryption key": "14, Failed to load data encryption key",
    "Failed to load data encryption key - Cache is full": _ERR_INTERNAL,
    "Failed to load data encryption key - Internal error": _ERR_INTERNAL,
    "Failed to load data encryption key - No such key": _ERR_INTERNAL,
    "Failed to mask output data": _ERR_UNPROTECT_FAILED,
    "Failed to reset policy": _ERR_INTERNAL,
    "Failed to send logs, connection refused !": "51, Failed to send logs, connection refused !",
    "Failed to set authorization": _ERR_INTERNAL,
    "Failed to set first call in cache": _ERR_INTERNAL,
    "Failed to strip date": _ERR_BUFFER_TOO_SMALL,
    "Failed to unstrip date": _ERR_INVALID_CONTENT,
    "Hash operation failed": _ERR_UNSUPPORTED_ACTION,
    "IV can't be used with this token element": _ERR_UNSUPPORTED_ACTION,
    "IV is not supported with used encoding": _ERR_UNSUPPORTED_ACTION,
    "Input is null or not within allowed limits.": _ERR_INPUT_LIMITS,
    "Input or output buffer is too small.": _ERR_BUFFER_TOO_SMALL,
    "Integrity check failed": _ERR_BUFFER_TOO_SMALL,
    "Integrity check failed.": "5, Integrity check failed.",
    "Internal error": _ERR_INPUT_LIMITS,
    "Internal error occurring in a function call after the Pep Provider has been opened.": _ERR_INTERNAL,
    "Invalid CT header format": "7, Data protection failed.",
    "Invalid UNICODE input data": _ERR_INVALID_CONTENT,
    "Invalid date format": _ERR_INVALID_CONTENT,
    "Invalid date input": _ERR_INVALID_CONTENT,
    "Invalid email address": _ERR_INVALID_CONTENT,
    "Invalid email address, domain length > 254": _ERR_DATA_TOO_LONG,
    "Invalid email address, total length > 256": _ERR_DATA_TOO_LONG,
    "Invalid email address, wrong domain length": _ERR_DATA_TOO_LONG,
    "Invalid email address, wrong local length": _ERR_INVALID_CONTENT,
    "Invalid input data": _ERR_INVALID_CONTENT,
    "Invalid input data for FPE creditcard": _ERR_INVALID_CONTENT,
    "Invalid input for the creditcard FPE type": _ERR_INVALID_CONTENT,
    "Invalid input for the creditcard token type": _ERR_INVALID_CONTENT,
    "Invalid input for the decimal token type": _ERR_INVALID_CONTENT,
    "Invalid input parameter": _ERR_INVALID_CONTENT,
    "Invalid license or time is before licensestart.": "42, Invalid license or time is before licensestart.",
    "Invalid parameter": _ERR_BUFFER_TOO_SMALL,
    "Invalid shared memory contents": _ERR_UNSUPPORTED_ACTION,
    "Invalid time format": _ERR_INVALID_CONTENT,
    "Invalid tokenproc": _ERR_INPUT_LIMITS,
    "Invalid use of Hmac Data Element": _ERR_UNSUPPORTED_ACTION,
    "Luhn value must be invalid": _ERR_INVALID_CONTENT,
    "Luhn value must be valid": _ERR_INVALID_CONTENT,
    "Malloc for the JSON type failed.": "30, Malloc for the JSON type failed.",
    "Manage protection operation failed.": "37, Manage protection operation failed.",
    "Manage protection operation was successful.": "36, Manage protection operation was successful.",
    "No such token element": "UNSUPPORTED_ENCODING",
    "No token elements available": _ERR_DE_NOT_FOUND,
    "No valid license or current date is beyond the license expiration date.": "40, No valid license or current date is beyond the license expiration date.",
    "Out buffer size is too small": _ERR_INPUT_LIMITS,
    "Output buffer is to small": _ERR_DATA_TOO_LONG,
    "Output buffer is too small": _ERR_INTERNAL,
    "Output encoding is not supported for Masking": _ERR_INPUT_LIMITS,
    "Permission denied": "33, Delete operation failed.",
    "Pointer to the policy shared memory is null": _ERR_INPUT_LIMITS,
    "Policy not available": _ERR_INTERNAL,
    "Protected value can't be returned for this type of algorithm": _ERR_PERMISSION_ONLY,
    "Provider not initialized": _ERR_INTERNAL,
    "Rule Set not found": "RULESET_NOT_FOUND",
    "The IV value is too long": _ERR_INPUT_LIMITS,
    "The IV value is too short": _ERR_INPUT_LIMITS,
    "The JSON type is not serializable.": "29, The JSON type is not serializable.",
    "The User has appropriate permissions to perform the requested operation but no data has been protected/unprotected.": _ERR_PERMISSION_ONLY,
    "The content of the input data is not valid.": _ERR_INVALID_CONTENT,
    "The data element could not be found in the policy in shared memory.": _ERR_DE_NOT_FOUND,
    "The data element is not using key id": "0, ",
    "The input is too long": _ERR_DATA_TOO_LONG,
    "The input is too short": "22, Data is too short to be protected/unprotected.",
    "The policy in shared memory is empty.": "31, Policy not available",
    "The policy in shared memory is locked. This can be caused by a disk full alert.": "39, The policy in memory is locked. This can be caused by a disk full alert.",
    "The requested action is not supported for tokenization": _ERR_INTERNAL,
    "The tokenized email became too long": _ERR_BUFFER_TOO_SMALL,
    "The use of the protection method is restricted by license.": "41, The use of the protection method is restricted by license.",
    "The user does not have the appropriate permissions to perform the requested operation.": "3, The user does not have the appropriate permissions to perform the requested operation.",
    "The username could not be found in the policy in shared memory.": "1, The username could not be found in the policy.",
    "Token value identification position is bigger than the data": _ERR_INPUT_LIMITS,
    "Token value identification position is invalid": _ERR_INVALID_CONTENT,
    "Tokenization is disabled": _ERR_UNSUPPORTED_ACTION,
    "Tweak generation is failed": _ERR_INTERNAL,
    "Tweak input is too long": "15, Tweak input is too long.",
    "Tweak is null.": "4, Tweak is null.",
    "Unsupported algorithm or unsupported action for the specific data element.": _ERR_UNSUPPORTED_ACTION,
    "Unsupported input encoding for the specific data element.": "UNSUPPORTED_ENCODING",
    "Unsupported operation for that datatype": _ERR_UNSUPPORTED_ACTION,
    "Unsupported tokenizer type.": _ERR_UNSUPPORTED_ACTION,
    "Unsupported tweak action for the specified fpe dataelement": "19, Unsupported tweak action for the specified fpe dataelement",
    "Unsupported version": _ERR_UNSUPPORTED_ACTION,
    "Used for z/OS Query Default Data element when policy name is not found": "46, Used for z/OS Query Default Data element when policy name is not found.",
    "Username too long.": _ERR_UNPROTECT_FAILED,
    "iconv failed - 8859-15 to system": _ERR_INTERNAL,
    "iconv failed - system to 8859-15": _ERR_INTERNAL,
    "User not authorized. Refer to audit log for details.": "3, The user does not have the appropriate permissions to perform the requested operation.",
    "Data element not found. Refer to audit log for details.": _ERR_DE_NOT_FOUND,
    "Integer input error. Only digits allowed":"44, The content of the input data is not valid.",
    "Integer input out of range. Valid values are -2147483648 to 2147483647":"44, The content of the input data is not valid.",
    "Invalid data length":"44, The content of the input data is not valid.",
    "Integer input out of range. Valid values are -2147483648 to 2147483647":"44, The content of the input data is not valid.",
    "Invalid base64-encoded data, character out of range":"26, Unsupported algorithm or unsupported action for the specific data element."
}
