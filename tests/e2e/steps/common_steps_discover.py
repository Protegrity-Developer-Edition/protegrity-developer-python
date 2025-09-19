from pathlib import Path
import allure
from dotenv import load_dotenv
import pytest
from pytest_bdd import then, parsers, when
from utils.helper import normalize_and_clean

load_dotenv()

@when(parsers.parse('the user invokes the "{function}" function with the following input text:'))
@when(parsers.parse('the user invokes the "{function}" function with empty input text:'))
def call_function(function, protegrity_developer_python_module, shared_vars, docstring):
	if docstring == "EMPTY":
		input = ""
	else:
		input = docstring.strip()

	try:
		if function == "find_and_protect":
			shared_vars["result"] = protegrity_developer_python_module.find_and_protect(input)
		elif function == "find_and_redact":
			shared_vars["result"] = protegrity_developer_python_module.find_and_redact(input)
		else:
			pytest.fail(f"Unsupported function name: {function}")

		shared_vars["original"] = input
	except Exception as e:
		if docstring == "EMPTY":
			shared_vars["input_error"] = str(e)
			return
		else:
			pytest.fail(f"{function} raised an exception: {str(e)}")

	if not shared_vars["result"]:
		pytest.fail(f"{function} returned an empty output.")

@when(parsers.parse('the user invokes the "{method}" function with the input file "{input_filename}"'))
def call_find_and_redact_with_file(method, protegrity_developer_python_module, shared_vars, test_configs, input_filename: str):
	input_file = Path(test_configs["user_input_path"]) / input_filename

	with open(input_file, "r", encoding="utf-8") as infile:
		input_lines = []
		output_lines = []
		for line in infile:
			try:
				line = line.rstrip()
				if line:
					if method == "find_and_redact":
						output = protegrity_developer_python_module.find_and_redact(line)
					elif method == "find_and_protect":
						output = protegrity_developer_python_module.find_and_protect(line)
					input_lines.append(line)
					output_lines.append(output)
			except Exception as e:
				pytest.fail(
					f"find_and_redact raised an exception with empty input: {str(e)}"
				)
		shared_vars["result"] = "\n".join(output_lines)
		shared_vars["original"] = "\n".join(input_lines)
		print(shared_vars["result"])

@when(
	parsers.parse(
		'the user invokes the "{function}" function with the input file "{input_filename}" too large'
	)
)
def call_function_with_file(
	function, protegrity_developer_python_module, shared_vars, test_configs, input_filename: str
):
	input_file = Path(test_configs["user_input_path"]) / input_filename

	with open(input_file, "r", encoding="utf-8") as f:
		input_text = f.read().replace("\n", "")

	try:
		if function == "find_and_redact":
			shared_vars["result"] = protegrity_developer_python_module.find_and_redact(
				input_text
			)
		else:
			shared_vars["result"] = protegrity_developer_python_module.find_and_protect(
				input_text
			)
	except Exception as e:
		shared_vars["input_error"] = str(e)
		return

@then("the output should be redacted as follows:")
@then("the output should be protected as follows:")
@then("the output should be masked as follows:")
@then("the output should be same as the input as follows:")
@then('the output should be redacted as follows by defaulting to "redact" method:')
def verify_output_text(shared_vars, docstring):
	allure.dynamic.description(
		"🚨 IMPORTANT: There is a known issue where sensitive data may not always be redacted or masked as expected. As a result, the 'then' steps may not fail even if redaction is incomplete or inaccurate."
	)

	print(shared_vars["result"])

	expected_output = docstring.strip()
	actual_output = shared_vars["result"]
	assert (
		actual_output == expected_output
	), f"Protected/Redacted/Masked output does not match expected output.\n"

@then(parsers.parse('the redacted output should match with the expected output in "{expected_output_filename}"'))
@then(parsers.parse('the masked output should match with the expected output in "{expected_output_filename}"'))
@then(parsers.parse('the protected output should match with the expected output in "{expected_output_filename}"'))
def verify_output_file(shared_vars, test_configs, expected_output_filename):
	exp_output_file = (
		Path(test_configs["redact_mask_exp_out_path"]) / expected_output_filename
	)

	if "prot" in expected_output_filename:
		exp_output_file = (
		Path(test_configs["find_protect_exp_out_path"]) / expected_output_filename
	)

	with open(exp_output_file, "r", encoding="utf-8") as f:
		output_text = f.read()

	actual = normalize_and_clean(shared_vars["result"])
	expected = normalize_and_clean(output_text)

	assert actual == expected, (
		"Redacted output does not match expected output.\n"
		f"Expected: {expected}\n"
		f"Actual: {actual}"
	)

@then(parsers.parse('the error should be seen as "{exp_error_msg}"'))
def verify_error_message(shared_vars, exp_error_msg):
	assert (
		exp_error_msg in shared_vars["input_error"]
	), f"Error message does not match expected error message.\nActual error: {shared_vars['input_error']}\nExpected error: {exp_error_msg}"
		