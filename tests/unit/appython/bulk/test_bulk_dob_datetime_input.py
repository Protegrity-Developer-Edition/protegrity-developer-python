from datetime import datetime
from appython import Protector,Charset
from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking

def test_bulk_datetime():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            None,
            datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
            datetime.strptime("2000/02/03", "%Y/%m/%d").date(), 
            datetime.strptime("1998/11/10", "%Y/%m/%d").date(),
            datetime.strptime("1975-12-25", "%Y-%m-%d").date(),
            datetime.strptime("1990/07/15", "%Y/%m/%d").date()
        ]
        
        protected = session.protect(input_data, "dob")
        un_protected = session.unprotect(protected[0], "dob")

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]

# dob does not support external_iv, so commenting out exiv tests
# def test_datetime_exiv():
#     protector = Protector()
#     session = protector.create_session("superuser")
#     input_data = [
#         datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
#         datetime.strptime("2000/02/03", "%Y/%m/%d").date()
#     ]
    
#     protected = session.protect(input_data, "dob",external_iv=bytes("exiv","utf-8"))
#     un_protected = session.unprotect(protected[0], "dob",external_iv=bytes("exiv","utf-8"))

#     for index in range(len(input_data)):
#         assert input_data[index] == un_protected[0][index]

def test_datetime_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
            datetime.strptime("2000/02/03", "%Y/%m/%d").date()
        ]
        
        try:
            session.protect(input_data, "dob",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.unprotect(input_data, "dob",external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: external_iv!! Expected: bytes, Actual: <class 'str'>"

def test_datetime_re_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
            datetime.strptime("2000/02/03", "%Y/%m/%d").date()
        ]
        
        protected = session.protect(input_data, "dob",external_iv=bytes("exiv","utf-8"))
        un_protected = session.unprotect(protected[0], "dob",external_iv=bytes("exiv","utf-8"))

        for index in range(len(input_data)):
            assert input_data[index] == un_protected[0][index]

def test_datetime_invalid_charset():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
            datetime.strptime("2000/02/03", "%Y/%m/%d").date()
        ]
        
        try:
            session.protect(input_data, "dob",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"
        try:
            session.unprotect(input_data, "dob",charset=Charset.UTF8)
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Charset is only supported with byte input data type"

def test_datetime_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = [
            datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
            datetime.strptime("2000/02/03", "%Y/%m/%d").date()
        ]
        
        try:
            session.protect(input_data, "dob")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."
        try:
            session.unprotect(input_data, "dob")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_datetime_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = [
            datetime.strptime("1985-06-30", "%Y-%m-%d").date(),
            datetime.strptime("2000/02/03", "%Y/%m/%d").date()
        ]
        
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
