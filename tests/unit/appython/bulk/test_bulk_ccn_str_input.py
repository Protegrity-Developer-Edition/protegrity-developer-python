from appython import Protector,Charset
from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking

def test_bulk_ccn():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            None,
            "4321567898765432",
            "5555444433332222", 
            "4111111111111111",
            "378282246310005",
            "6011000990139424"
        ]
        
        protected = session.protect(input_data, "ccn")
        un_protected = session.unprotect(protected[0], "ccn")

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]

def test_ccn_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            "4321567898765432",
            "5555444433332222", 
            "4111111111111111",
            "378282246310005"
        ]
        
        protected = session.protect(input_data, "ccn",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected[0], "ccn",external_iv=bytes("exiv","utf-8"))

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]

def test_ccn_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.protect(input_data, "ccn",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "ccn",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_ccn_re_invalid_exiv(): 
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_ccn_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.protect(input_data, "ccn",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "ccn",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_ccn_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.protect(input_data, "ccn")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "ccn")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_ccn_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
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

def test_str_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            "4321567898765432",
            "5555444433332222", 
            "4111111111111111",
            "378282246310005"
        ]
        
        protected = session.protect(input_data, "ccn",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected[0], "ccn",external_iv=bytes("exiv","utf-8"))

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]

def test_str_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.protect(input_data, "ccn",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "ccn",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_str_re_invalid_exiv(): 
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_str_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.protect(input_data, "ccn",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "ccn",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.reprotect(input_data, "ccn","SUCCESS_REPROTECT_STR",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_str_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
        try:
            session.protect(input_data, "ccn")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "ccn")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_str_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
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
        input_data = ["4321567898765432", "5555444433332222", "4111111111111111"]
        
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
