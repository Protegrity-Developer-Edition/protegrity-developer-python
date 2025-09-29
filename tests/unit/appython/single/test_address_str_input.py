from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking
from appython import Protector,Charset

def test_str(): 
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
        protected = session.protect(input_data, "address")
        un_protected = session.unprotect(protected, "address")
        # reprotected = session.reprotect(protected, "address","SUCCESS_REPROTECT_STR")
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_STR")
        # assert protected != reprotected
        assert un_protected == input_data
        # assert re_unprotected == input_data

def test_str_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
        protected = session.protect(input_data, "address",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected, "address",external_iv=bytes("exiv","utf-8"))
        # reprotected = session.reprotect(protected, "address","SUCCESS_REPROTECT_STR",old_external_iv=bytes("oldexiv","utf-8"),new_external_iv=bytes("newexiv","utf-8"))
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_STR",external_iv=bytes("newexiv","utf-8"))
        #assert protected != reprotected
        assert un_protected == input_data
        #assert # re_unprotected == input_data

def test_str_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
        try:
            session.protect(input_data, "address",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "address",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_str_re_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
        try:
            session.reprotect(input_data, "address","SUCCESS_REPROTECT_STR",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "address","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "address","SUCCESS_REPROTECT_STR",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_str_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
        try:
            session.protect(input_data, "address",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "address",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.reprotect(input_data, "address","SUCCESS_REPROTECT_STR",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_str_invalid_useraddress():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
        try:
            session.protect(input_data, "address")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "address")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        # try:
        #     session.reprotect(input_data, "address","SUCCESS_REPROTECT_STR")
        # except Exception as e:
        #     assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_str_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Johannesburg International Technology Park, 4567 Nelson Mandela Innovation Drive, Building 12A, Floor 45, Suite 2301-2305, Sandton Central Business District, Johannesburg Metropolitan Municipality, Gauteng Province 2196, Republic of South Africa, Southern Africa Regional Headquarters"
        
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
        #     session.reprotect(input_data, "address","INVALID_DE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."



