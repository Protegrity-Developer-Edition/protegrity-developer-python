from appython import Protector,Charset
from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking

def test_bulk_str():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [None,"Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
        protected = session.protect(input_data, "name")
        un_protected = session.unprotect(protected[0], "name")
        # reprotected = session.reprotect(protected[0], "name","SUCCESS_REPROTECT_STR")
        # re_unprotected = session.unprotect(reprotected[0], "SUCCESS_REPROTECT_STR")

        # for index in range(len(input_data)):
        #     if input_data[index] is not None:
        #         assert protected[0][index] != reprotected[0][index]

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]
        
        # for index in range(len(input_data)):
        #     assert input_data[index] == re_unprotected[0][index]

def test_str_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
        protected = session.protect(input_data, "name",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected[0], "name",external_iv=bytes("exiv","utf-8"))
        # reprotected = session.reprotect(protected[0], "name","SUCCESS_REPROTECT_STR",old_external_iv=bytes("oldexiv","utf-8"),new_external_iv=bytes("newexiv","utf-8"))
        # re_unprotected = session.unprotect(reprotected[0], "SUCCESS_REPROTECT_STR",external_iv=bytes("newexiv","utf-8"))
    
        # for index in range(len(input_data)):
        #     assert protected[0][index] != reprotected[0][index]

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]
    
        # for index in range(len(input_data)):
        #     assert input_data[index] == re_unprotected[0][index]

def test_str_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
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

def test_str_re_invalid_exiv(): 
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_str_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
        try:
            session.protect(input_data, "name",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "name",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_str_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = ["Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
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
        #     session.reprotect(input_data, "name","SUCCESS_REPROTECT_STR")
        # except Exception as e:
        #     assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_str_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["Protegrity","AP_PYTHON_TEST","STR_BULK  TEST WITH SPACE"]
        
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
        #     session.reprotect(input_data, "INVALID_DE","SUCCESS_REPROTECT_STR")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "name","INVALID_DE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."



