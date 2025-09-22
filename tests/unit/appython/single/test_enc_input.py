from tests.unit.appython.mock.mocks import start_protect_unprotect_mocking
import math
from appython import Protector

def test_str_enc_byte_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Protegrity"
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=bytes)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=bytes)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,bytes))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,bytes))

        assert un_protected.decode("utf-8") == input_data
        # assert re_unprotected.decode("utf-8") == input_data

def test_str_enc_str_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Protegrity"
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=str)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=str)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,str))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,str))

        assert un_protected == input_data
        # assert re_unprotected == input_data
    
def test_int_enc_int_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 12345
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=int)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=int)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,int))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,int))

        assert un_protected == input_data
        # assert re_unprotected == input_data

def test_float_enc_float_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = 123.45
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=float)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=float)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,float))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,float))

        assert math.isclose(un_protected,input_data,rel_tol=1e-9,abs_tol=0.0)
        # assert math.isclose(re_unprotected,input_data,rel_tol=1e-9,abs_tol=0.0)

def test_byte_enc_utf8_byte_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=bytes)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=bytes)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,bytes))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,bytes))

        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_byte_enc_utf16le_byte_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-16le"
        input_data = bytes("Protegrity",encoding)
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=bytes)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=bytes)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,bytes))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,bytes))
        
        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_byte_enc_utf16be_byte_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-16be"
        input_data = bytes("Protegrity",encoding)
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=bytes)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=bytes)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,bytes))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,bytes))
        
        assert un_protected.decode(encoding) == input_data.decode(encoding)
        # assert re_unprotected.decode(encoding) == input_data.decode(encoding)

def test_byte_enc_utf8_str_dec():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        encoding = "utf-8"
        input_data = bytes("Protegrity",encoding)
        
        protected = session.protect(input_data, "name",encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",decrypt_to=str)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",decrypt_to=str)
        
        assert(isinstance(protected,bytes))
        assert(isinstance(un_protected,str))
        # assert(isinstance(reprotected,bytes))
        # assert(isinstance(re_unprotected,str))

        assert un_protected == input_data.decode(encoding)
        # assert re_unprotected == input_data.decode(encoding)

def test_str_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = "Protegrity"
        
        protected = session.protect(input_data, "name",external_iv=bytes("exiv","utf-8"),encrypt_to=bytes)
        un_protected = session.unprotect(protected, "name",external_iv=bytes("exiv","utf-8"),decrypt_to=str)
        # reprotected = session.reprotect(protected, "name","SUCCESS_REPROTECT_ENC",old_external_iv=bytes("oldexiv","utf-8"),new_external_iv=bytes("newexiv","utf-8"),encrypt_to=bytes)
        # re_unprotected = session.unprotect(reprotected, "SUCCESS_REPROTECT_ENC",external_iv=bytes("newexiv","utf-8"),decrypt_to=str)
        # assert protected != reprotected
        assert un_protected == input_data
        # assert re_unprotected == input_data

def test_str_protect_unprotect_invalid_exiv():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = bytes("Protegrity","utf-8")
        
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
        input_data = bytes("Protegrity","utf-8")
        
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_ENC",old_external_iv="inv",new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: old_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_ENC",old_external_iv=bytes("exiv","utf-8"),new_external_iv="inv")
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, Invalid Keyword Type for keyword: new_external_iv!! Expected: bytes, Actual: <class 'str'>"
        try:
            session.reprotect(input_data, "name","SUCCESS_REPROTECT_ENC",old_external_iv=bytes("exiv","utf-8"))
            assert False, "Expected an exception but none was raised"
        except Exception as e:
            assert str(e) == "-1, old_external_iv and new_external_iv both are required for reprotect operation !"

def test_str_invalid_username():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("ALL_INVALID")
        input_data = bytes("Protegrity","utf-8")
        
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
        #     session.reprotect(input_data, "name","SUCCESS_REPROTECT_ENC")
        # except Exception as e:
        #     assert str(e) == "3, The user does not have the appropriate permissions to perform the requested operation."

def test_str_invalid_data_element():
    with start_protect_unprotect_mocking():
        protector = Protector()
        session = protector.create_session("superuser")
        input_data = bytes("Protegrity","utf-8")
        
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
        #     session.reprotect(input_data, "INVALID_DE","SUCCESS_REPROTECT_ENC")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."
        # try:
        #     session.reprotect(input_data, "name","INVALID_ENC_DE")
        # except Exception as e:
        #     assert str(e) == "2, The data element could not be found in the policy."
    
# def test_str_enc_str_dec():
#     protector = Protector()
#     session = protector.create_session("superuser")
#     input_data = "Protegrity"
    
#     try:
#         session.protect(input_data, "name")
#     except Exception as e:
#         assert str(e) == "26, Unsupported algorithm or unsupported action for the specific data element."
#     try:
#         session.unprotect(input_data, "name")
#     except Exception as e:
#         assert str(e) == "26, Unsupported algorithm or unsupported action for the specific data element."
#     try:
#         session.reprotect(input_data, "name", "REPROTECT_SUCCESS_ENC")
#     except Exception as e:
#         assert str(e) == "26, Unsupported algorithm or unsupported action for the specific data element."
