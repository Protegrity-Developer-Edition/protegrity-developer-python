from typing import Any
from pytest_bdd import scenarios, when, then, parsers
from utils.helper import parse_input_data, generate_long_input_data
from appython.protector import Protector
from appython.protector import Session

# Following feature files are using the steps defined in this file
scenarios("../features/single_data_protection_negative.feature")
scenarios("../features/bulk_data_protection_negative.feature")

@when(parsers.parse('the user performs "{operation}" operation using "{method}" method on the "{input_type}" input data "{input}" using "{data_element}" data element with the username "{user}"'))
@when(parsers.parse('the user performs "{operation}" operation using "{method}" method on the "{input_type}" input data "{input}" using "{data_element}" data element with the username "{user}" after the session has expired "{session_timeout}"'))
@when(parsers.parse('the user performs "{operation}" operation using "{method}" method on the "{input_type}" input data "{input}" using "{data_element}" data element with the username "{user}" with invalid data type for session timeout "{session_timeout}"'))
def perform_operation(operation: str, method:str, input_type:str, input: str, data_element: str, user: str, shared_vars: dict[Any], protector_instance: Protector, session_timeout: str = None):
	flag: bool = False
	output = None
	error_msg = None
	err_codes = None

	if session_timeout is not None and session_timeout != "string_timeout":
		session_timeout = float(session_timeout)

	if input.startswith("InputDataMoreThan_"):
		if "Bulk" in input:
			input = generate_long_input_data(input, data_element, input_type)
		else:
			input = generate_long_input_data(input, data_element)

	input_data = parse_input_data(input, input_type)

	if data_element == "data_type_int":
		data_element = 123
	elif data_element == "Empty":
		data_element = ""
	elif data_element == "None":
		data_element = None

	if user == "data_type_int":
		user = 123
	elif user == "Empty":
		user = ""
	elif user == "None":
		user = None

	try:
		session: Session = protector_instance.create_session(user, session_timeout)

		if method == "tokenization":
			if "list" in input_type or "tuple" in input_type:
				if operation == "protect":
					output, err_codes = session.protect(input_data, data_element)
				elif operation == "unprotect":
					output, err_codes = session.unprotect(input_data, data_element)
				elif operation == "reprotect":
					output, err_codes = session.reprotect(input_data, data_element, data_element)
				else:
					raise ValueError(f"Unsupported operation: {operation}")
			else:
				if operation == "protect":
					output = session.protect(input_data, data_element)
				elif operation == "unprotect":
					output = session.unprotect(input_data, data_element)
				elif operation == "reprotect":
					output = session.reprotect(input_data, data_element, data_element)
				else:
					raise ValueError(f"Unsupported operation: {operation}")
		else:
			if "list" in input_type or "tuple" in input_type:
				if operation == "protect":
					output, err_codes = session.protect(input_data, data_element, encrypt_to=bytes)
				elif operation == "unprotect":
					if "bytes" in input_type:
						output, err_codes = session.unprotect(input_data, data_element, decrypt_to=bytes)
					elif "string" in input_type:
						output, err_codes = session.unprotect(input_data, data_element, decrypt_to=str)
					elif "integer" in input_type:
						output, err_codes = session.unprotect(input_data, data_element, decrypt_to=int)
					else:
						raise("Unsupported input type for decryption")
				elif operation == "reprotect":
					output, err_codes = session.reprotect(input_data, data_element, data_element, encrypt_to=bytes)
				else:
					raise ValueError(f"Unsupported operation: {operation}")
			else:
				if operation == "protect":
					output = session.protect(input_data, data_element, encrypt_to=bytes)
				elif operation == "unprotect":
					if "bytes" in input_type:
						output = session.unprotect(input_data, data_element, decrypt_to=bytes)
					elif "string" in input_type:
						output = session.unprotect(input_data, data_element, decrypt_to=str)
					elif "integer" in input_type:
						output = session.unprotect(input_data, data_element, decrypt_to=int)
					else:
						raise("Unsupported input type for decryption")
					
					# Convert to hex string
					if output is not None:
						output = output.hex()
				elif operation == "reprotect":
					output = session.reprotect(input_data, data_element, data_element,encrypt_to=bytes)
				else:
					raise ValueError(f"Unsupported operation: {operation}")
	except Exception as exc:
		flag = True
		error_msg = str(exc)

	shared_vars["negative_result"] = {
		"result": flag,
		"error_message": error_msg,
		"output": output,
		"err_codes": err_codes
	}

	# print(shared_vars["negative_result"])


@when(parsers.parse('the user performs "{operation}" operation using "{method}" method on the "{input_type}" input data "{input}" using "{data_element}" data element with the username "{user}" and external IV as "{eiv}"'))
def perform_operation(operation: str, method:str, input_type:str, input: str, data_element: str, user: str, eiv: str, shared_vars: dict[Any], protector_instance: Protector):
	flag: bool = False
	output = None
	error_msg = None
	err_codes = None

	if input.startswith("InputDataMoreThan_"):
		input = generate_long_input_data(input, data_element)

	if eiv == "data_type_string":
		eiv = "ext1234"
	else:
		eiv = bytes(eiv, encoding="utf-8")

	input_data = parse_input_data(input, input_type)

	try:
		session: Session = protector_instance.create_session(user)

		if method == "tokenization":
			if "list" in input_type or "tuple" in input_type:
					if operation == "protect":
						output, err_codes = session.protect(input_data, data_element, external_iv=eiv)
					elif operation == "unprotect":
						output, err_codes = session.unprotect(input_data, data_element, external_iv=eiv)
					elif operation == "reprotect":
						output, err_codes = session.reprotect(input_data, data_element, data_element, old_external_iv=eiv, new_external_iv=eiv)
					else:
						raise ValueError(f"Unsupported operation: {operation}")
			else:
				if operation == "protect":
					output = session.protect(input_data, data_element, external_iv=eiv)
				elif operation == "unprotect":
					output = session.unprotect(input_data, data_element, external_iv=eiv)
				elif operation == "reprotect":
					output = session.reprotect(input_data, data_element, data_element, old_external_iv=eiv, new_external_iv=eiv)
				else:
					raise ValueError(f"Unsupported operation: {operation}")
		else:
			if operation == "protect":
					output = session.protect(input_data, data_element, encrypt_to=bytes, external_iv=eiv)
			elif operation == "unprotect":
				if "bytes" in input_type:
					output = session.unprotect(input_data, data_element, decrypt_to=bytes, external_iv=eiv)
				elif "string" in input_type:
					output = session.unprotect(input_data, data_element, decrypt_to=str, external_iv=eiv)
				elif "integer" in input_type:
					output = session.unprotect(input_data, data_element, decrypt_to=int, external_iv=eiv)
				else:
					raise("Unsupported input type for decryption")
				
				# Convert to hex string
				output = output.hex()
			elif operation == "reprotect":
				output = session.reprotect(input_data, data_element, data_element,encrypt_to=bytes, external_iv=eiv)
			else:
				raise ValueError(f"Unsupported operation: {operation}")
	except Exception as exc:
		flag = True
		error_msg = str(exc)

	shared_vars["negative_result"] = {
		"result": flag,
		"error_message": error_msg,
		"output": output,
		"err_codes": err_codes
	}

	# print(shared_vars["negative_result"])