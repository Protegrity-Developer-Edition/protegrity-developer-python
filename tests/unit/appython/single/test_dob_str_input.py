from appython import Protector,Charset
from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking

def test_str():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "1998/11/10"
        
        protected = session.protect(input_data, "dob")
        un_protected = session.unprotect(protected, "dob")
        # reprotected = session.reprotect(protected, "dob","SUCCESS_REPROTECT_STR")
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_STR")
        # assert protected != reprotected
        assert un_protected == input_data
        # assert re_unprotected == input_data
        
# exiv related tests are commented as external_iv is not supported for dob data element
def test_str_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "1998/11/10"
        
        protected = session.protect(input_data, "dob",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected, "dob",external_iv=bytes("exiv","utf-8"))
        # reprotected = session.reprotect(protected, "dob","SUCCESS_REPROTECT_STR",old_external_iv=bytes("oldexiv","utf-8"),new_external_iv=bytes("newexiv","utf-8"))
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_STR",external_iv=bytes("newexiv","utf-8"))
        #assert protected != reprotected
        assert un_protected == input_data
        #assert # re_unprotected == input_data

def test_str_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "1998/11/10"
        
        try:
            session.protect(input_data, "dob",external_iv="inv")
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "dob",external_iv="inv")
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_str_re_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "1998/11/10"
        
        try:
            session.reprotect(input_data, "dob","SUCCESS_REPROTECT_STR",old_external_iv="inv",new_external_iv="inv")
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "dob","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "dob","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"))
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_str_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "1998/11/10"
        
        try:
            session.protect(input_data, "dob",charset=Charset.UTF8)
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "dob",charset=Charset.UTF8)
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.reprotect(input_data, "dob","SUCCESS_REPROTECT_STR",charset=Charset.UTF8)
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_str_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = "1998/11/10"
        
        try:
            session.protect(input_data, "dob")
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "dob")
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        # try:
        #     session.reprotect(input_data, "dob","SUCCESS_REPROTECT_STR")
        # except Exception as e:
        #     assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_str_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "1998/11/10"
        
        try:
            session.protect(input_data, "INVALID_DE")
        except Exception as e:
            assert str(e) == "2, The data element could not be found in the policy."
        try:
            session.unprotect(input_data, "INVALID_DE")
        except Exception as e:
            assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "INVALID_DE","SUCCESS_REPROTECT_STR")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "dob","INVALID_DE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."



