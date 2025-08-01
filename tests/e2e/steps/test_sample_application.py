import os
import pytest
import subprocess
from pytest_bdd import scenarios, given, when, then, parsers
from utils.helper import modify_method_in_config

scenarios("../features/sample_app.feature")


@pytest.fixture
def shared_output():
    return {}


@given(
    parsers.parse('python version 3.9 or higher is installed as "{python_executable}"')
)
def python_version_for_subprocess(shared_output, python_executable):
    shared_output["python_executable"] = python_executable


@when(
    parsers.parse(
        'the user runs the sample app with method configured as "{method}" in config.json file'
    )
)
def run_app(test_configs, protegrity_developer_python_env, shared_output, method):
    sample_app = test_configs["app_file"]
    config_file = test_configs["sample_config_file"]
    python = shared_output.get("python_executable", "python")
    env = protegrity_developer_python_env

    if method == "mask":
        modify_method_in_config(config_file, "mask")
    else:
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
        'the output.txt file containing named entity labels should match with "{expected_output_file}" file'
    )
)
@then(
    parsers.parse(
        'the output.txt file containing masking characters should match with "{expected_output_file}" file'
    )
)
def verify_output_file(test_configs, expected_output_file):
    output_file = test_configs["output_file"]
    expected_output_path = test_configs["expected_output_path"]

    expected_file = os.path.join(expected_output_path, expected_output_file)

    with open(output_file, "r") as actual_file, open(expected_file, "r") as file:
        actual_content = actual_file.read().strip()
        expected_content = file.read().strip()

    assert (
        actual_content == expected_content
    ), f"Redacted/Masked output does not match expected output. Actual output: {actual_content}"
