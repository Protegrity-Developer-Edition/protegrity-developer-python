# -*- coding: utf-8 -*-

"""
.. module:: protector
    :synopsis: This module contains APIs for protect, unprotect, reprotect operations.
"""
from enum import Enum
from datetime import datetime
import os
from appython.utils.exceptions import (
    ProtectError,
    UnprotectError,
    ReprotectError,
    InvalidSessionError,
    ProtectorError,
    InitializationError,
)

from appython.utils.input_preprocessor import InputPreprocessor
from appython.service.payload_builder import PayloadBuilder
from appython.service.request_handler import RequestHandler
from appython.service.response_handler import ResponseHandler
from appython.service.auth_token_provider import AuthTokenProvider


class Charset(Enum):
    UTF8 = 2
    UTF16LE = 4
    UTF16BE = 5


class Protector(object):
    """Protector class consists of all the APIs for protection operations."""

    def create_session(self, policy_user, timeout=15, **kwargs):
        """This method creates a new session with specified timeout value.

        With valid Sessions you can perform the protection operations like
        protect, unprotect, or reprotect.

        Args:
            policy_user (str): User name defined in the policy
            timeout (int, optional): Session timeout, specified in minutes.
                By default, the value of this parameter is set to 15.
            **kwargs: Futuristic, currently no keyword arguments accepted.

        Returns:
            session: Object of the :class:`Session` class. This stores the user's current session
                and provides all the Protection APIs.

        Raises:
            ProtectorError: If the policy user is passed null or empty.

        Usage::

            >>> from appython import Protector
            >>> protector = Protector()
            >>> session = protector.create_session("superuser")

        """
        if not policy_user:
            raise ProtectorError(err_msg="-1, Policy user cannot be none or empty")
        session = Session(policy_user, timeout, **kwargs)
        return session

    def get_version(self):
        """Return the version of the AP Python in use.

        The version number can be compared with that of the PEP Server package to ensure that both are the same.

        Returns:
            str: The Product version

        Usage::

            from appython import Protector
            protector = Protector()
            protector.get_version()

        """
        return "1.0.0"

    def get_version_ex(self):
        """Returns the extended version of the AP Python in use.

        The extended version consists of AP-Python version number and Core Version number.
        Core version number can be communicated to the Protegrity Support
        while troubleshooting AP-Python related issues.

        Returns:
            str: The Product version and Core version

        Usage::

            from appython import Protector
            protector = Protector()
            protector.get_version_ex()

        """
        return "SDK Version: 1.0.0, Core Version: 1.0.0"

    def terminate(self):
        return True


class Session(object):
    """Session class holds user session and provides Protection APIs.

    A session object needs to be created first using create_session() API
    of the Protector object. Using this object one can invoke
    protection methods like protect, unprotect or reprotect on it.

    Session object becomes invalid if remained idle for the specified
    timeout period. Any operation with an invalid session leads to
    exception.
    """

    def __init__(self, user, ttl, **kwargs):

        try:
            api_key, jwt_token = self.authenticate()
            self.api_key = api_key
            self.jwt_token = jwt_token
        except Exception as e:
            raise InitializationError(err_msg=f"{e}")

        self._user = user
        if ttl is None:
            self._ttl = 15 * 60
        elif not (isinstance(ttl, int) or isinstance(ttl, float)):
            raise ValueError("timeout must be an integer or float value!!")
        else:
            self._ttl = int(ttl * 60)  # in seconds
        self._timestamp = datetime.now()
        self._closed = False

    def authenticate(self):
        """Authenticate the user with the given email and password.

        Args:
            email (str): Email for authentication.
            password (str): Password for authentication.

        Raises:
            InitializationError: If authentication fails.

        """
        email = os.environ.get("DEV_EDITION_EMAIL", None)
        password = os.environ.get("DEV_EDITION_PASSWORD", None)
        api_key = os.environ.get("DEV_EDITION_API_KEY", None)

        if not email or not password:
            raise InitializationError(
                err_msg="Authentication failed: Both DEV_EDITION_EMAIL and DEV_EDITION_PASSWORD must be provided."
            )

        if not api_key:
            raise InitializationError(
                err_msg="Authentication failed: DEV_EDITION_API_KEY must be provided."
            )
        # Authenticate and get the JWT token
        response = AuthTokenProvider.get_jwt_token(email, password,api_key)
        if response.status_code != 200:
            raise InitializationError(
                err_msg=f"{response.json().get('error', 'Could not authenticate user.')}"
            )
        return api_key, response.json().get("jwt_token", None)

    def __validate(self):
        cur_time = datetime.now()
        delta = (cur_time - self._timestamp).seconds
        if delta >= self._ttl:
            raise InvalidSessionError(err_msg="User session is invalid or timed out!!")
        else:
            self._timestamp = cur_time

    def protect(self, data, de, **kwargs):
        """Protect data using tokenization, data type preservation, no encryption,
         or encryption data element.

        It supports single as well as bulk protection without a maximum data limit.
        However, you are recommended not to pass more than 1 MB of input data
        for each protection call. For String and byte data types,
        the maximum length for tokenization is 4096 bytes, while for
        encryption no maximum length is defined.

        It accepts data of following types:
            - str
            - bytes (future bytes)
            - int
            - long
            - float
            - datetime
            - List (of same data types)
            - Tuple (of same data types)

        Args:
            data (obj): Data to be protected. You can provide the data of above mentioned types.
            de (str): String containing the data element name defined in policy.
            **kwargs: Specify one or more of the following keyword arguments:
                - external_iv: Specify the external initialization vector for
                    Tokenization and FPE protection methods.
                - encrypt_to: Specify this argument for encrypting the data and set its value
                    to bytes. This argument is mandatory for encryption, except if you want
                    to encrypt byte data. This argument is not used for Tokenization and
                    FPE protection methods.
                - external_tweak: Specify the external tweak value for FPE protection method.

        Returns:
            Protected data. In case of bulk, a tuple of output list(or tuple) and a tuple of
                error codes is returned.

        Raises:
            ProtectError: This exception is thrown if the API is unable to protect the single data.
                For Bulk, no exception is thrown.
            InvalidSessionError : This exception is thrown if the session is invalid or has timed out.

        Usage::

            >>> from appython import Protector
            >>> protector = Protector()
            >>> session = protector.create_session("superuser")
            >>> session.protect("Protegrity1", "name")
            Pr9zdglWRy1

            External IV
            -----------
            >>> session.protect("Protegrity1", "name", external_iv=bytes("1234"))
            PrksvEshuy1

            Bulk Call
            ---------
            >>> data = ["protegrity1234", "Protegrity1", "Protegrity56"]
            >>> out, error_list = session.protect(data, "name")
            >>> print("Protected Data: ")
            >>> print(out)
            >>> print("Error List: ")
            >>> print(error_list)
            Protected Data:
            ['prMLJsM8fZUp34', 'Pr9zdglWRy1', 'Pra9Ez5LPG56']
            Error List:
            (6, 6, 6)

        """
        self.__validate()
        try:
            input = InputPreprocessor.convert_input_to_string(
                data, kwargs, de, "protect"
            )
            arguments = InputPreprocessor.validate_parameters(
                kwargs, input["input_datatype"], "protect", self._user, de
            )
            payload, return_type, base_url = PayloadBuilder.build_api_request(
                input, arguments, "protect"
            )
            response = RequestHandler.send_api_request(
                payload, base_url, self.api_key, self.jwt_token
            )
            result = ResponseHandler.process(response, return_type, "protect")
            return result

        except Exception as e:
            raise ProtectError(err_msg=e)

    def unprotect(self, data, de, **kwargs):
        """Unprotect the protected data in its original form.

        It supports both single as well bulk operations.

        It accepts data of following types:
            - str
            - bytes (future bytes)
            - int
            - long
            - float
            - datetime
            - List (of same data types)
            - Tuple (of same data types)

        Args:
            data (obj): Data to be unprotected. You can provide the data of above mentioned types.
            de (str): String containing the data element name defined in policy.
            **kwargs: Specify one or more of the following keyword arguments:
                - external_iv: Specify the external initialization vector for
                    Tokenization and FPE protection methods.
                - decrypt_to: Specify this argument for decrypting the data and set its value
                    to the data type of the original data. For example, if you are unprotecting
                    a string data, then you must specify the output data type as str.
                    This argument is mandatory, except if you want to decrypt bytes data.
                    This argument is not used for Tokenization and FPE protection methods.
                - external_tweak: Specify the external tweak value for FPE protection method.

        Returns:
            Unprotected data. In case of bulk, a tuple of output list(or tuple) and a tuple of
                error codes is returned.

        Raises:
            UnprotectError: This exception is thrown if the API is unable to unprotect the single data.
                For Bulk, no exception is thrown.
            InvalidSessionError : This exception is thrown if the session is invalid or has timed out.

        Usage::

            >>> from appython import Protector
            >>> protector = Protector()
            >>> session = protector.create_session("superuser")
            >>> output = session.protect("Protegrity1", "name")
            >>> print("Protected Data: %s" %output)
            >>> org = session.unprotect(output, "name")
            >>> print("Unprotected Data: %s" %org)

            Protected Data: Pr9zdglWRy1
            Unprotected Data: Protegrity1

            External IV
            -----------
            >>> output = session.protect("Protegrity1", "name", external_iv=bytes("1234"))
            >>> print("Protected Data: %s" %output)
            >>> org = session.unprotect(output, "name", external_iv=bytes("1234"))
            >>> print("Unprotected Data: %s" %org)

            Protected Data: PrksvEshuy1
            Unprotected Data: Protegrity1

            Bulk Call
            ---------
            >>> data = ["protegrity1234", "Protegrity1", "Protegrity56"]
            >>> p_out = session.protect(data, "name")
            >>> print("Protected Data: ")
            >>> print(p_out)
            >>> out = session.unprotect(p_out[0], "name")
            >>> print("Unprotected Data: ")
            >>> print(out)

            Protected Data:
            (['prMLJsM8fZUp34', 'Pr9zdglWRy1', 'Pra9Ez5LPG56'], (6, 6, 6))
            Unprotected Data:
            (['protegrity1234', 'Protegrity1', 'Protegrity56'], (8, 8, 8))
        """
        self.__validate()
        try:
            input = InputPreprocessor.convert_input_to_string(
                data, kwargs, de, "unprotect"
            )
            arguments = InputPreprocessor.validate_parameters(
                kwargs, input["input_datatype"], "unprotect", self._user, de
            )
            payload, return_type, base_url = PayloadBuilder.build_api_request(
                input, arguments, "unprotect"
            )
            response = RequestHandler.send_api_request(
                payload, base_url, self.api_key, self.jwt_token
            )
            result = ResponseHandler.process(response, return_type, "unprotect")
            return result
        except Exception as e:
            raise UnprotectError(err_msg=e)

    def reprotect(self, data, old_de, new_de, **kwargs):
        """Reprotect data using tokenization, data type preservation, no encryption,
        or encryption data element.

        The protected data is first unprotected and then protected again with a new data element.
        It supports bulk protection without a maximum data limit. However, you are recommended
        not to pass more than 1 MB of input data for each protection call. Both old and
        new data elements should be of the tokenization type.

        For String and byte data types, the maximum length for tokenization is 4096 bytes,
        while for encryption no maximum length is defined.

        It accepts data of following types:
            - str
            - bytes (future bytes)
            - int
            - long
            - float
            - datetime
            - List (of same data types)
            - Tuple (of same data types)

        Args:
            data (str): Protected data to be reprotected. The data is first unprotected with the
                old data element and then protected with the new data element.
            old_de (str): String containing the data element name defined in the policy for the
                input data. This data element is used to unprotect the protected data as part of
                the reprotect operation.
            new_de (str): String containing the data element name defined in the policy to create
                the output data. This data element is used to protect the data as part of the
                reprotect operation.
            **kwargs: Specify one or more of the following keyword arguments:
                - old_external_iv: Specify the external initialization vectors for Tokenization
                    and FPE protection methods. These arguments are Optional.
                - new_external_iv: Specify the external initialization vectors for Tokenization
                    and FPE protection methods. These arguments are Optional.
                - old_external_tweak: Specify the external tweak values for FPE protection method.
                     These arguments are Optional.
                - new_external_tweak: Specify the external tweak values for FPE protection method.
                     These arguments are Optional.

        Returns:
            Reprotected data. In case of bulk, a tuple of output list(or tuple) and a tuple of
                error codes is returned.

        Raises:
            ReprotectError: This exception is thrown if the API is unable to reprotect the single data.
                For Bulk, no exception is thrown.
            InvalidSessionError: This exception is thrown if the session is invalid or has timed out.

        Usage::

            >>> from appython import Protector
            >>> protector = Protector()
            >>> session = protector.create_session("superuser")
            >>> output = session.protect("Protegrity1", "name")
            >>> print("Protected Data: %s" %output)
            >>> r_out = session.reprotect(output, "name", "SUCCESS_REPROTECT_STR")
            >>> print("Reprotected Data: %s" %r_out)

            Protected Data: Pr9zdglWRy1
            Reprotected Data: 7gD6aY1Aja9

            External IV
            -----------
            >>> p_out = session.protect("Protegrity1", "name",
            >>> external_iv=bytes("1234"))
            >>> print("Protected Data: %s" %p_out)
            >>> r_out = session.reprotect(p_out, "name",
            "SUCCESS_REPROTECT_STR", old_external_iv=bytes("1234"),
            >>> new_external_iv=bytes("123456"))
            >>> print("Reprotected Data: %s" %r_out)

            Protected Data: PrksvEshuy1
            Reprotected Data: PrKxfmdTGy1

            Bulk Call
            ---------
            >>> data = ["protegrity1234", "Protegrity1", "Protegrity56"]
            >>> p_out = session.protect(data, "name")
            >>> print("Protected Data: ")
            >>> print(p_out)
            >>> r_out = session.reprotect(p_out[0], "name", "SUCCESS_REPROTECT_STR")
            >>> print("Reprotected Data: ")
            >>> print(r_out)

            Protected Data:
            (['pLAvXYIAbp5234', 'P8PCmC8gty1', 'PHNjXrw7Iy56'], (6, 6, 6))
            Reprotected Data:
            (['prMLJsM8fZUp34', 'Pr9zdglWRy1', 'Pra9Ez5LPG56'], (6, 6, 6))
        """
        self.__validate()
        try:
            input = InputPreprocessor.convert_input_to_string(
                data, kwargs, new_de, "reprotect"
            )
            arguments = InputPreprocessor.validate_parameters(
                kwargs, input["input_datatype"], "reprotect", self._user, old_de, new_de
            )
            payload, return_type, base_url = PayloadBuilder.build_api_request(
                input, arguments, "reprotect"
            )
            response = RequestHandler.send_api_request(
                payload, base_url, self.api_key, self.jwt_token
            )
            result = ResponseHandler.process(response, return_type, "reprotect")
            return result
        except Exception as e:
            raise ReprotectError(err_msg=e)

    def flush_audits(self):
        self.__validate()
        return True

    def check_access(self, de, access_type, newde=None):
        """Return access permission status of the user for a specified data element.

        Args:
            de (str): String containing the data element name defined in policy.
            access_type (CheckAccessType): Type of the access of the user for the data element.
                You can specify a value for this parameter from the CheckAccessType enumeration.
                    - CheckAccessType.PROTECT
                    - CheckAccessType.UNPROTECT
                    - CheckAccessType.REPROTECT

        Returns:
            bool: True if the user has access, else False.

        Raises:
            InvalidSessionError: This exception is thrown if the session is invalid or has timed out.
            PyCoreProviderError: This exception is thrown if unable to check access.

        Usage::

            >>> from appython import Protector
            >>> from appython import CheckAccessType
            >>> protector = Protector()
            >>> session = protector.create_session("User1")
            >>> print(session.check_access("AlphaNumeric", CheckAccessType.REPROTECT))
            True

        """
        self.__validate()
        return True

    def __close_session(self):
        self._provider = None
        self._timestamp = None
        self._ttl = None
        self._user = None
        self._closed = True

    def __repr__(self):
        return "Session(user=%s)" % (self._user)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.flush_audits()
        self.__close_session()

    def __del__(self):
        if hasattr(self, "_closed") and not self._closed:
            self.__close_session()
