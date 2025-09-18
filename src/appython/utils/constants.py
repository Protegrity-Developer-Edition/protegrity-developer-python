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

HOST = "api-test.developer-edition.protegrity.com"
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

ERROR_MAPPING = {
    "Access Key security groups not found": "ACCESSKEY_NOT_FOUND",
    "Alphabet was not found": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Application has been authorized.": "27, Application has been authorized.",
    "Application has not been authorized.": "28, Application has not been authorized.",
    "Bulk re-protect is not supported": "51, Failed to send logs, connection refused !",
    "Card type must be invalid input": "44, The content of the input data is not valid.",
    "Card type must be valid input": "44, The content of the input data is not valid.",
    "Create operation failed.": "35, Create operation failed.",
    "Create operation was successful.": "34, Create operation was successful.",
    "Crypto operation failed": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Data is too long to be protected/unprotected": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Data is too long to be protected/unprotected.": "23, Data is too long to be protected/unprotected.",
    "Data is too short to be protected/unprotected.": "22, Data is too short to be protected/unprotected.",
    "Data protect operation failed.": "7, Data protection failed.",
    "Data protect operation was successful.": "6, Data protection was successful.",
    "Data reprotect operation was successful.": "50, Data protection was successful.",
    "Data unprotect operation failed.": "9, Data unprotect operation failed.",
    "Data unprotect operation was successful with use of an inactive keyid.": "11, Data unprotect operation was successful with use of an inactive keyid.",
    "Data unprotect operation was successful.": "8, Data unprotect operation was successful.",
    "Delete operation failed.": "33, Delete operation failed.",
    "Delete operation was successful.": "32, Delete operation was successful.",
    "Encoding must be provided": "12, Input is null or not within allowed limits.",
    "Encoding not supported": "UNSUPPORTED_ENCODING",
    "External IV is not supported in this version": "16, External IV is not supported in this version.",
    "FPE value identification position is bigger than the data": "12, Input is null or not within allowed limits.",
    "FPE value identification position is invalid": "44, The content of the input data is not valid.",
    "Failed to acquire policy mutex": "17, Failed to initialize the PEP - This is a fatal error",
    "Failed to allocate memory.": "20, Failed to allocate memory.",
    "Failed to calculate policy hash": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to check for first call": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to clear key context": "10, The user has the appropriate permissions to perform the requested operation. This is just a policy check and no data has been protected nor unprotected.",
    "Failed to convert input data": "21, Input or output buffer is too small.",
    "Failed to convert output data": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to convert padded input data": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to create Alphabet mutex": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to create event for flush thread": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to create key context": "10, The user has the appropriate permissions to perform the requested operation. This is just a policy check and no data has been protected nor unprotected.",
    "Failed to create log mutex": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to create policy Mutex": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to get binary alphabet": "21, Input or output buffer is too small.",
    "Failed to get session from cache": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to initialize crypto library": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to initialize the PEP - This is a fatal error": "17, Failed to initialize the PEP - This is a fatal error",
    "Failed to load Alphabet from Shmem": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to load FPE Properties from Shmem": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to load FPE prop - Internal error": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to load FPE prop - No such element": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to load data encryption key": "14, Failed to load data encryption key",
    "Failed to load data encryption key - Cache is full": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to load data encryption key - Internal error": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to load data encryption key - No such key": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to mask output data": "9, Data unprotect operation failed.",
    "Failed to reset policy": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to send logs, connection refused !": "51, Failed to send logs, connection refused !",
    "Failed to set authorization": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to set first call in cache": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Failed to strip date": "21, Input or output buffer is too small.",
    "Failed to unstrip date": "44, The content of the input data is not valid.",
    "Hash operation failed": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "IV can't be used with this token element": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "IV is not supported with used encoding": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Input is null or not within allowed limits.": "12, Input is null or not within allowed limits.",
    "Input or output buffer is too small.": "21, Input or output buffer is too small.",
    "Integrity check failed": "21, Input or output buffer is too small.",
    "Integrity check failed.": "5, Integrity check failed.",
    "Internal error": "12, Input is null or not within allowed limits.",
    "Internal error occurring in a function call after the Pep Provider has been opened.": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Invalid CT header format": "7, Data protection failed.",
    "Invalid UNICODE input data": "44, The content of the input data is not valid.",
    "Invalid date format": "44, The content of the input data is not valid.",
    "Invalid date input": "44, The content of the input data is not valid.",
    "Invalid email address": "44, The content of the input data is not valid.",
    "Invalid email address, domain length > 254": "23, Data is too long to be protected/unprotected.",
    "Invalid email address, total length > 256": "23, Data is too long to be protected/unprotected.",
    "Invalid email address, wrong domain length": "23, Data is too long to be protected/unprotected.",
    "Invalid email address, wrong local length": "44, The content of the input data is not valid.",
    "Invalid input data": "44, The content of the input data is not valid.",
    "Invalid input data for FPE creditcard": "44, The content of the input data is not valid.",
    "Invalid input for the creditcard FPE type": "44, The content of the input data is not valid.",
    "Invalid input for the creditcard token type": "44, The content of the input data is not valid.",
    "Invalid input for the decimal token type": "44, The content of the input data is not valid.",
    "Invalid input parameter": "44, The content of the input data is not valid.",
    "Invalid license or time is before licensestart.": "42, Invalid license or time is before licensestart.",
    "Invalid parameter": "21, Input or output buffer is too small.",
    "Invalid shared memory contents": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Invalid time format": "44, The content of the input data is not valid.",
    "Invalid tokenproc": "12, Input is null or not within allowed limits.",
    "Invalid use of Hmac Data Element": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Luhn value must be invalid": "44, The content of the input data is not valid.",
    "Luhn value must be valid": "44, The content of the input data is not valid.",
    "Malloc for the JSON type failed.": "30, Malloc for the JSON type failed.",
    "Manage protection operation failed.": "37, Manage protection operation failed.",
    "Manage protection operation was successful.": "36, Manage protection operation was successful.",
    "No such token element": "UNSUPPORTED_ENCODING",
    "No token elements available": "2, The data element could not be found in the policy.",
    "No valid license or current date is beyond the license expiration date.": "40, No valid license or current date is beyond the license expiration date.",
    "Out buffer size is too small": "12, Input is null or not within allowed limits.",
    "Output buffer is to small": "23, Data is too long to be protected/unprotected.",
    "Output buffer is too small": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Output encoding is not supported for Masking": "12, Input is null or not within allowed limits.",
    "Permission denied": "33, Delete operation failed.",
    "Pointer to the policy shared memory is null": "12, Input is null or not within allowed limits.",
    "Policy not available": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Protected value can't be returned for this type of algorithm": "10, The user has the appropriate permissions to perform the requested operation. This is just a policy check and no data has been protected nor unprotected.",
    "Provider not initialized": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Rule Set not found": "RULESET_NOT_FOUND",
    "The IV value is too long": "12, Input is null or not within allowed limits.",
    "The IV value is too short": "12, Input is null or not within allowed limits.",
    "The JSON type is not serializable.": "29, The JSON type is not serializable.",
    "The User has appropriate permissions to perform the requested operation but no data has been protected/unprotected.": "10, The user has the appropriate permissions to perform the requested operation. This is just a policy check and no data has been protected nor unprotected.",
    "The content of the input data is not valid.": "44, The content of the input data is not valid.",
    "The data element could not be found in the policy in shared memory.": "2, The data element could not be found in the policy.",
    "The data element is not using key id": "0, ",
    "The input is too long": "23, Data is too long to be protected/unprotected.",
    "The input is too short": "22, Data is too short to be protected/unprotected.",
    "The policy in shared memory is empty.": "31, Policy not available",
    "The policy in shared memory is locked. This can be caused by a disk full alert.": "39, The policy in memory is locked. This can be caused by a disk full alert.",
    "The requested action is not supported for tokenization": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "The tokenized email became too long": "21, Input or output buffer is too small.",
    "The use of the protection method is restricted by license.": "41, The use of the protection method is restricted by license.",
    "The user does not have the appropriate permissions to perform the requested operation.": "3, The user does not have the appropriate permissions to perform the requested operation.",
    "The username could not be found in the policy in shared memory.": "1, The username could not be found in the policy.",
    "Token value identification position is bigger than the data": "12, Input is null or not within allowed limits.",
    "Token value identification position is invalid": "44, The content of the input data is not valid.",
    "Tokenization is disabled": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Tweak generation is failed": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "Tweak input is too long": "15, Tweak input is too long.",
    "Tweak is null.": "4, Tweak is null.",
    "Unsupported algorithm or unsupported action for the specific data element.": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Unsupported input encoding for the specific data element.": "UNSUPPORTED_ENCODING",
    "Unsupported operation for that datatype": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Unsupported tokenizer type.": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Unsupported tweak action for the specified fpe dataelement": "19, Unsupported tweak action for the specified fpe dataelement",
    "Unsupported version": "26, Unsupported algorithm or unsupported action for the specific data element.",
    "Used for z/OS Query Default Data element when policy name is not found": "46, Used for z/OS Query Default Data element when policy name is not found.",
    "Username too long.": "9, Data unprotect operation failed.",
    "iconv failed - 8859-15 to system": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "iconv failed - system to 8859-15": "13, Internal error occurring in a function call after the Core Provider has been opened.",
    "User not authorized. Refer to audit log for details.": "3, The user does not have the appropriate permissions to perform the requested operation.",
    "Data element not found. Refer to audit log for details.": "2, The data element could not be found in the policy.",
    "Integer input error. Only digits allowed":"44, The content of the input data is not valid.",
    "Integer input out of range. Valid values are -2147483648 to 2147483647":"44, The content of the input data is not valid.",
    "Invalid data length":"44, The content of the input data is not valid.",
    "Integer input out of range. Valid values are -2147483648 to 2147483647":"44, The content of the input data is not valid.",
    "Invalid base64-encoded data, character out of range":"26, Unsupported algorithm or unsupported action for the specific data element."
}
