import math
from appython import Protector,Charset
import pytest
from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking

def test():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 3.142
        
        protected = session.protect(input_data, "number")
        un_protected = session.unprotect(protected, "number")
        # reprotected = session.reprotect(protected, "number","SUCCESS_REPROTECT_FLOAT")
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_FLOAT")
        
        assert math.isclose(un_protected,input_data,rel_tol=1e-9,abs_tol=0.0)
        # assert math.isclose(re_unprotected,input_data,rel_tol=1e-9,abs_tol=0.0)

@pytest.mark.skip(reason="Test is correct but skipping since playground sending wrong output")
def test_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 3.142
        
        protected = session.protect(input_data, "number",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected, "number",external_iv=bytes("exiv","utf-8"))
        # reprotected = session.reprotect(protected, "number","SUCCESS_REPROTECT_FLOAT",old_external_iv=bytes("oldexiv","utf-8"),new_external_iv=bytes("newexiv","utf-8"))
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_FLOAT",external_iv=bytes("newexiv","utf-8"))
        assert math.isclose(un_protected,input_data,rel_tol=1e-9,abs_tol=0.0)
        # assert math.isclose(re_unprotected,input_data,rel_tol=1e-9,abs_tol=0.0)

def test_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 3.142
        
        try:
            session.protect(input_data, "number",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "number",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_re_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 3.142
        
        try:
            session.reprotect(input_data, "number","SUCCESS_REPROTECT_FLOAT",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "number","SUCCESS_REPROTECT_FLOAT",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "number","SUCCESS_REPROTECT_FLOAT",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 3.142
        
        try:
            session.protect(input_data, "number",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "number",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.reprotect(input_data, "number","SUCCESS_REPROTECT_FLOAT",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = 3.142
        
        try:
            session.protect(input_data, "number")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "number")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        # try:
        #     session.reprotect(input_data, "number","SUCCESS_REPROTECT_FLOAT")
        # except Exception as e:
        #     assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 3.142
        
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
        #     session.reprotect(input_data, "INVALID_DE","SUCCESS_REPROTECT_FLOAT")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "number","INVALID_DE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."



