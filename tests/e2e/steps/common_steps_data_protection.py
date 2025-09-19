import os
import ast
from typing import Any
from pytest_bdd import given, then, parsers
		
@given("protegrity_developer_python module is installed")
@given("the appython module is available via the protegrity_developer_python installation")
@given("the enviroment variables DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD and DEV_EDITION_API_KEY are set")
@given("sample application is present")
@given("config.json is present")
@given("a sample input file containing PII data")
@given("docker-compose.yml is up and running")
@given("a policy is deployed with required data elements, users and permissions required to test the scenario")
def do_nothing():
	pass

@given(parsers.parse('a policy is deployed with required data elements and user "{user}" is present'))
def get_user(user, shared_vars):
	shared_vars["user"] = user

@then("all the data is validated")
def validate_all_data(shared_vars):
	results = shared_vars["file_line"]
	for result in results:
		assert result["protected"] != result["input"], "Protected data should differ from input data"
		assert result["unprotected"] == result["input"], "Unprotected data should match original input data"

@then("all the data is validated for eiv")
def validate_all_data(shared_vars):
	results = shared_vars["file_line"]
	for result in results:
		assert result["protected_iv"] != result["input"], "Protected data with IV should differ from input data"
		assert result["protected_iv"] != result["protected"], "Protected data with IV should differ from protected data"
		assert result["unprotected_iv"] == result["input"], "Unprotected data with IV should match original input data"

@then(parsers.parse('all the data should be written to a file "{filename}"'))
def write_all_results_to_file(shared_vars, filename, test_configs):
	results = shared_vars["file_line"]
	results_dir = test_configs["protection_results_path"]
	os.makedirs(results_dir, exist_ok=True)
	output_path = os.path.join(results_dir, filename)

	# Delete existing file to start fresh
	if os.path.exists(output_path):
		os.remove(output_path)

	# Write header and each result as a line, with keys and values separated by pipe "|"
	with open(output_path, "w", encoding="utf-8") as f:
		f.write(shared_vars["file_header"])
		for result in results:
			keys = list(result.keys())
			values = [str(result[k]) for k in keys]
			row = " | ".join(values) + "\n"
			f.write(row)

@then(parsers.parse('the result is "{exp_result}", the error message should be "{exp_err_msg}" and output as "{exp_out}"'))
@then(parsers.parse('the result is "{exp_result}", the error message should be "{exp_err_msg}", output as "{exp_out}" and error codes as "{error_codes}"'))
def verify_error_and_output(exp_result: str, exp_err_msg: str, exp_out: str, shared_vars: dict[Any], error_codes: str=None):
	# Verify if exception was thrown if expected
	if exp_result == "exception":
		assert shared_vars["negative_result"]["result"] is True, "Expected an exception but the operation succeeded."
	else:
		assert shared_vars["negative_result"]["result"] is False, f"Exception thrown when it was not expected. Error message: {shared_vars['negative_result']['error_message']}"

	# Verify the error message
	if exp_err_msg == "None":
		exp_err_msg = None
	assert shared_vars["negative_result"]["error_message"] == exp_err_msg, f"Expected error message as '{exp_err_msg}' but got '{shared_vars['negative_result']['error_message']}'"

	# Verify the output returned
	if exp_out == "None":
		exp_out = None
	# Try to convert exp_out to Python object if actual output is not a string
	actual_out = shared_vars["negative_result"]["output"]
	if exp_out is not None:
		try:
			if isinstance(actual_out, (list, tuple, int, float)) and isinstance(exp_out, str):
				exp_out = ast.literal_eval(exp_out)
			elif hasattr(actual_out, 'isoformat') and isinstance(exp_out, str):
				from datetime import datetime
				for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d"):
					try:
						exp_out = datetime.strptime(exp_out, fmt)
						break
					except Exception:
						continue
		except Exception:
			pass

	if error_codes is not None:
		error_codes = ast.literal_eval(error_codes)
		assert shared_vars["negative_result"]["err_codes"] == error_codes, f"Expected error codes as '{error_codes}' but got '{shared_vars['negative_result']['err_codes']}'"

	assert actual_out == exp_out, f"Expected output as '{exp_out}' but got '{actual_out}'"