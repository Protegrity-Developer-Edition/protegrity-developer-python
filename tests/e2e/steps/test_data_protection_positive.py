import os
import sys
import json
from typing import List, Any
from pytest_bdd import scenarios, when, parsers
from utils.helper import parse_input_data, append_result_template, append_result_template_eiv, parse_output_data_for_enc
from appython.protector import Session

# Following feature files are using the steps defined in this file
scenarios("../features/string_input_data_protection.feature")
scenarios("../features/integer_input_data_protection.feature")
scenarios("../features/bytes_input_data_protection.feature")
scenarios("../features/date_input_data_protection.feature")

@when(parsers.parse('the user performs "{method}" operations on the "{input_type}" input data using the following data elements'))
@when(parsers.parse('the user performs "{method}" operations on the "{input_type}" using the following data elements'))
def protection_operations(datatable:List[List[Any]], session: Session, shared_vars: dict[Any], method: str, input_type: str):
	for row in datatable[1:]:
		data_element: str = row[0]	

		input_data: Any = parse_input_data(row[1], input_type)
		
		try:
			if method == "tokenization":
				if "list" in input_type or "tuple" in input_type:
					# Tokenize the input data list/tuple
					protected, err_codes = session.protect(input_data, data_element)
					# Detokenize the protected data list/tuple
					unprotected, err_codes = session.unprotect(protected, data_element)
				else:
					# Tokenize the input data
					protected = session.protect(input_data, data_element)
					# Detokenize the protected data
					unprotected = session.unprotect(protected, data_element)
			else:
				if "list" in input_type or "tuple" in input_type:
					# Encrypt the input data list/tuple
					protected, err_codes = session.protect(input_data, data_element, encrypt_to=bytes)
					# Decrypt the encrypted data list/tuple
					if "bytes" in input_type:
						unprotected, err_codes = session.unprotect(protected, data_element, decrypt_to=bytes)
					elif "string" in input_type:
						unprotected, err_codes = session.unprotect(protected, data_element, decrypt_to=str)
					elif "integer" in input_type:
						unprotected, err_codes = session.unprotect(protected, data_element, decrypt_to=int)
					else:
						raise("Unsupported input type for decryption")
				else:
					# Encrypt the input data
					protected = session.protect(input_data, data_element, encrypt_to=bytes)
					# Decrypt the encrypted data
					if "bytes" in input_type:
						unprotected = session.unprotect(protected, data_element, decrypt_to=bytes)
					elif "string" in input_type:
						unprotected = session.unprotect(protected, data_element, decrypt_to=str)
					elif "integer" in input_type:
						unprotected = session.unprotect(protected, data_element, decrypt_to=int)
					else:
						raise("Unsupported input type for decryption")

				# Convert to hex string for comparison/validation
				input_data, protected, unprotected = parse_output_data_for_enc(input_data, protected, unprotected, input_type)
				
		except Exception as ex:
			print(
				f"Error: input={input_data}, data_element={data_element}, method={method}, input_type={input_type}, error={str(ex)}",
				file=sys.stderr)
			raise

		append_result_template(
			shared_vars=shared_vars,
			method=method,
			input_type=input_type,
			user=shared_vars["user"],
			data_element=data_element,
			input_data=input_data,
			protected=protected,
			unprotected=unprotected
		)

		shared_vars["file_header"] = "METHOD | INPUT_TYPE | USER | PROTECT_DATA_ELEMENT | ORIGINAL_DATA | PROTECTED_DATA | UNPROTECTED_DATA\n"

@when(parsers.parse('the user performs "{method}" operations on the "{input_type}" input data using the following data elements and external IV'))
@when(parsers.parse('the user performs "{method}" operations on the "{input_type}" using the following data elements and external IV'))
def protection_operations_eiv(datatable: List[List[Any]], session: Session, shared_vars: dict[Any], method: str, input_type: str):
	for row in datatable[1:]:
		data_element = row[0]  
		eiv = row[2]

		input_data = parse_input_data(row[1], input_type)

		try:
			if "list" in input_type or "tuple" in input_type:
				# Tokenize the input data list/tuple
				protected, err_codes = session.protect(input_data, data_element)
				# Tokenize the input data list/tuple with IV
				protected_iv, err_codes = session.protect(input_data, data_element, external_iv=bytes(eiv, encoding="utf-8"))
				# Detokenize the protected data list/tuple with IV
				unprotected_iv, err_codes = session.unprotect(protected_iv, data_element, external_iv=bytes(eiv, encoding="utf-8"))
			else:
				# Tokenize the input data
				protected = session.protect(input_data, data_element)
				# Tokenize the input data with IV
				protected_iv = session.protect(input_data, data_element, external_iv=bytes(eiv, encoding="utf-8"))
				# Detokenize the protected data
				unprotected_iv = session.unprotect(protected_iv, data_element, external_iv=bytes(eiv, encoding="utf-8"))
			
		except Exception as ex:
			print(
				f"Error: input={input_data}, data_element={data_element}, eiv={eiv}, method={method}, input_type={input_type}, error={str(ex)}",
				file=sys.stderr)
			raise

		append_result_template_eiv(
			shared_vars=shared_vars,
			method=method,
			input_type=input_type,
			user=shared_vars["user"],
			data_element=data_element,
			eiv=eiv,
			input_data=input_data,
			protected=protected,
			protected_iv=protected_iv,
			unprotected_iv=unprotected_iv
		)

		shared_vars["file_header"] = "METHOD | INPUT_TYPE | USER | PROTECT_DATA_ELEMENT | EIV | ORIGINAL_DATA | PROTECTED_DATA | PROTECTED_DATA_IV | UNPROTECTED_DATA_IV\n"
