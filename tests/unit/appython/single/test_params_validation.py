from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking
from appython import Protector,Charset

def test_invalid_single():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = {"key":"value"}
        
        try:
            session.protect(input_data, "name")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported input data type <class 'dict'> !"
        try:
            session.unprotect(input_data, "name")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported input data type <class 'dict'> !"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported input data type <class 'dict'> !"

def test_invalid_bulk():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [None,{"key":"value"}]
        
        try:
            session.protect(input_data, "name")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported input data type <class 'dict'> !"
        try:
            session.unprotect(input_data, "name")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported input data type <class 'dict'> !"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported input data type <class 'dict'> !"

def test_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [bytes("Protegrity","utf-8")]
        
        try:
            session.protect(input_data, "name",charset=23)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported Charset Passed.Use the Charset enum to pass utf-8,utf-16le or utf-16be charset!"
        try:
            session.unprotect(input_data, "name",charset=23)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported Charset Passed.Use the Charset enum to pass utf-8,utf-16le or utf-16be charset!"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR",charset=23)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Unsupported Charset Passed.Use the Charset enum to pass utf-8,utf-16le or utf-16be charset!"

def test_invalid_reprotect_iv_test():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [bytes("Protegrity","utf-8")]
        
        try:
            session.reprotect(input_data,"name","SUCCESS_REPROTECT_STR",old_external_iv=bytes("iv","utf-8"),charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"
        try:
            session.reprotect(input_data,"name","SUCCESS_REPROTECT_STR",new_external_iv=bytes("iv","utf-8"),charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"
        try:
            session.reprotect(input_data,"name","SUCCESS_REPROTECT_STR",old_external_iv=bytes("iv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"
        try:
            session.reprotect(input_data,"name","SUCCESS_REPROTECT_STR",new_external_iv=bytes("iv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"
