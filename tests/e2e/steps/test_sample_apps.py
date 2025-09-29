import os
import pytest
import sys
import subprocess
from pytest_bdd import scenarios, given, when, then, parsers
from utils.helper import modify_method_in_config

scenarios("../features/sample_app_find_and_redact.feature")
scenarios("../features/sample_app_find_and_prot_unprot.feature")

@pytest.fixture
def shared_output():
    return {}

@when(
    parsers.parse(
        'the user runs the sample app "{sample_app}" with method configured as "{method}" in config.json file'
    )
)
@when(
    parsers.parse(
        'the user runs the sample app "{sample_app}"')
)
def run_app(test_configs, protegrity_developer_python_env, shared_output, sample_app, method=None):
    sample_app = test_configs[sample_app]
    config_file = test_configs["sample_config_file"]
    python = sys.executable
    env = protegrity_developer_python_env

    if method == "mask":
        modify_method_in_config(config_file, "mask")
    elif method == "redact":
        modify_method_in_config(config_file, "redact")

    try:
        subprocess.run(
            [python, sample_app], capture_output=True, text=True, check=True, env=env
        )
    except subprocess.CalledProcessError as e:
        pytest.fail(
            f"Script failed with return code {e.returncode}\nSTDERR: {e.stderr}"
        )
    except FileNotFoundError:
        pytest.fail("The script or Python interpreter was not found.")
    except Exception as e:
        pytest.fail(f"An unexpected error occurred: {str(e)}")


@then(
    parsers.parse(
        'the output file containing named entity labels should match with "{expected_output_file}" file'
    )
)
@then(
    parsers.parse(
        'the output file containing masking characters should match with "{expected_output_file}" file'
    )
)
def verify_output_file(test_configs, expected_output_file):
    expected_output_path = test_configs["find_protect_exp_out_path"]
    if "redact" in expected_output_file or "mask" in expected_output_file:
        output_file = test_configs["output_file_redact"]
        expected_output_path = test_configs["redact_mask_exp_out_path"]
    elif "protect" in expected_output_file:
        output_file = test_configs["output_file_protect"]
    else:
        output_file = test_configs["output_file_unprotect"]
        expected_output_path = test_configs["find_unprot_exp_out"]

    expected_file = os.path.join(expected_output_path, expected_output_file)

    with open(output_file, "r") as actual_file, open(expected_file, "r") as file:
        actual_content = actual_file.read().strip()
        expected_content = file.read().strip()

    assert (
        actual_content == expected_content
    ), f"Redacted/Masked output does not match expected output. Actual output: {actual_content}"
