from appython import Protector,Charset
from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking

def test_bytes_utf_8():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        charset_val = Charset.UTF8
        
        protected = session.protect(input_data, "name",charset=charset_val)
        un_protected = session.unprotect(protected, "name",charset=charset_val)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_BYTE",charset=charset_val)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_BYTE",charset=charset_val)

        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)


def test_bytes_utf_16le():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-16le"
        input_data = bytes("Protegrity",encoding)
        charset_val = Charset.UTF16LE
        
        protected = session.protect(input_data, "name",charset=charset_val)
        un_protected = session.unprotect(protected, "name",charset=charset_val)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_BYTE",charset=charset_val)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_BYTE",charset=charset_val)

        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_bytes_utf_16be():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-16be"
        input_data = bytes("Protegrity",encoding)
        charset_val = Charset.UTF16BE
        
        protected = session.protect(input_data, "name",charset=charset_val)
        un_protected = session.unprotect(protected, "name",charset=charset_val)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_BYTE",charset=charset_val)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_BYTE",charset=charset_val)

        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_bytes_utf_without_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        protected = session.protect(input_data, "name")
        un_protected = session.unprotect(protected, "name")
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_BYTE")
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_BYTE")

        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_bytes_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        protected = session.protect(input_data, "name",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected, "name",external_iv=bytes("exiv","utf-8"))
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_BYTE",old_external_iv=bytes("oldexiv","utf-8"),new_external_iv=bytes("newexiv","utf-8"))
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_BYTE",external_iv=bytes("newexiv","utf-8"))
        
        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_bytes_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        try:
            session.protect(input_data, "name",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "name",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_bytes_re_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_BYTE",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_BYTE",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_BYTE",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_bytes_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        try:
            session.protect(input_data, "name")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "name")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        # try:
        #     session.reprotect(input_data, "name","SUCCESS_REPROTECT_BYTE")
        # except Exception as e:
        #     assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_bytes_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        try:
            session.protect(input_data, "INVALID_DE")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "2, The data element could not be found in the policy."
        try:
            session.unprotect(input_data, "INVALID_DE")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "INVALID_DE","SUCCESS_REPROTECT_BYTE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "name","INVALID_DE_BYTE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."



