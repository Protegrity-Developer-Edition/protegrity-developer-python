import json
import pytest
from pathlib import Path
from pytest_bdd import scenarios, given, when, then

scenarios("../features/find_protect_unprotect.feature")


@pytest.fixture
def shared_vars():
	return {}


@given("the protegrity_developer_python module is configured")
def configure_protegrity_developer_python(
	protegrity_developer_python_module,
	test_configs
):
	config_file = Path(test_configs["mappings_config_file"])

	# Load configuration if available
	if config_file.exists():
		with open(config_file, "r") as f:
			config = json.load(f)
	else:
		raise FileNotFoundError(f"Configuration file not found: {config_file}")

	# Configure the protegrity_developer_python module
	protegrity_developer_python_module.configure(
		endpoint_url=config.get("endpoint_url"),
		named_entity_map=config.get("entity_mapping"),
		classification_score_threshold=config.get(
			"classification_score_threshold", 0.8
		),
		enable_logging=config.get("enable_logging", True),
		log_level=config.get("log_level", "info"),
	)


@when("the user invokes the find_and_unprotect function with the protected output")
def call_function(protegrity_developer_python_module, shared_vars):
	try:
		shared_vars["unprotected"] = protegrity_developer_python_module.find_and_unprotect(shared_vars["result"])
		print(shared_vars["unprotected"])
	except Exception as e:
		pytest.fail(f"find_and_unprotect raised an exception: {str(e)}")
			
	if not shared_vars["unprotected"]:
		pytest.fail(f"find_and_unprotect returned an empty output.")

	
@then('the unprotected output should match the original input')
def verify_output_text(shared_vars):
	expected_output = shared_vars["original"]
	actual_output = shared_vars["unprotected"]
	assert (
		actual_output == expected_output
	), f"Unprotected output does not match original data.\n"
