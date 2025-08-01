import json
import logging
import pytest
import allure
from pathlib import Path
from utils.helper import normalize_and_clean
from pytest_bdd import scenarios, given, when, then, parsers

scenarios("../features/protegrity_developer_python.feature")


@pytest.fixture
def shared_output():
    return {}


@given(
    parsers.parse(
        'the configuration file has "{method_key}" as "{method_value}" and protegrity_developer_python module is configured'
    )
)
def configure_protegrity_developer_python(
    protegrity_developer_python_module,
    test_configs,
    method_key,
    method_value,
    datatable,
):
    config_file = Path(test_configs["mappings_config_file"])

    # Load configuration if available
    if config_file.exists():
        with open(config_file, "r") as f:
            config = json.load(f)

    # Update the configuration with the key-value pair
    config[method_key] = method_value
    if datatable[1][0] != "NA":
        mask_char_key = datatable[0][0]
        mask_char_value = datatable[1][0]
        config[mask_char_key] = mask_char_value

    # Configure the protegrity_developer_python module
    protegrity_developer_python_module.configure(
        endpoint_url=config.get("endpoint_url"),
        named_entity_map=config.get("entity_mapping"),
        masking_char=config.get("masking_char"),
        classification_score_threshold=config.get(
            "classification_score_threshold", 0.8
        ),
        method=config.get("method"),
        enable_logging=True,
    )


@when("the user invokes the find_and_redact function with the following input text:")
@when("the user invokes the find_and_redact function with empty input text:")
def call_find_and_redact(protegrity_developer_python_module, shared_output, docstring):
    if docstring == "EMPTY":
        input = ""
    else:
        input = docstring.strip()

    try:
        shared_output["result"] = protegrity_developer_python_module.find_and_redact(
            input
        )
    except Exception as e:
        if docstring == "EMPTY":
            shared_output["input_error"] = str(e)
            return
        else:
            pytest.fail(
                f"find_and_redact raised an exception with empty input: {str(e)}"
            )

    if not shared_output["result"]:
        pytest.fail("find_and_redact returned an empty output.")


@then("the output should be redacted as follows:")
@then("the output should be masked as follows:")
@then("the output should be same as the input as follows:")
@then('the output should be redacted as follows by defaulting to "redact" method:')
def verify_output_text(shared_output, docstring):
    allure.dynamic.description(
        "🚨 IMPORTANT: There is a known issue where sensitive data may not always be redacted or masked as expected. As a result, the 'then' steps may not fail even if redaction is incomplete or inaccurate."
    )

    expected_output = docstring.strip()
    actual_output = shared_output["result"]
    assert (
        actual_output == expected_output
    ), f"Redacted/Masked output does not match expected output.\n"


@when(
    parsers.parse(
        'the user invokes the find_and_redact function with the input file "{input_filename}"'
    )
)
def call_find_and_redact_with_file(
    protegrity_developer_python_module, shared_output, test_configs, input_filename: str
):
    input_file = Path(test_configs["user_input_path"]) / input_filename

    with open(input_file, "r", encoding="utf-8") as infile:
        output_lines = []
        for line in infile:
            try:
                line = line.rstrip()
                if line:
                    output = protegrity_developer_python_module.find_and_redact(line)
                    output_lines.append(output)
            except Exception as e:
                pytest.fail(
                    f"find_and_redact raised an exception with empty input: {str(e)}"
                )
        shared_output["result"] = "\n".join(output_lines)
        # print(shared_output["result"])


@when(
    parsers.parse(
        'the user invokes the find_and_redact function with the input file "{input_filename}" too large'
    )
)
def call_find_and_redact_with_file(
    protegrity_developer_python_module, shared_output, test_configs, input_filename: str
):
    input_file = Path(test_configs["user_input_path"]) / input_filename

    with open(input_file, "r", encoding="utf-8") as f:
        input_text = f.read().replace("\n", "")

    try:
        shared_output["result"] = protegrity_developer_python_module.find_and_redact(
            input_text
        )
    except Exception as e:
        shared_output["input_error"] = str(e)
        return


@then(
    parsers.parse(
        'the redacted output should match with the expected output in "{expected_output_filename}"'
    )
)
@then(
    parsers.parse(
        'the masked output should match with the expected output in "{expected_output_filename}"'
    )
)
def verify_output_file(shared_output, test_configs, expected_output_filename):
    exp_output_file = (
        Path(test_configs["expected_output_path"]) / expected_output_filename
    )

    with open(exp_output_file, "r", encoding="utf-8") as f:
        output_text = f.read()

    actual = normalize_and_clean(shared_output["result"])
    expected = normalize_and_clean(output_text)

    assert actual == expected, (
        "Redacted output does not match expected output.\n"
        f"Expected: {expected}\n"
        f"Actual: {actual}"
    )


@then(parsers.parse('the error should be seen as "{exp_error_msg}"'))
def verify_error_message(shared_output, exp_error_msg):
    assert (
        exp_error_msg in shared_output["input_error"]
    ), f"Error message does not match expected error message.\nActual error: {shared_output['input_error']}\nExpected error: {exp_error_msg}"


@when(
    "the user calls the find_and_redact function with the following input text while capturing logs:"
)
def call_redact_and_track_logs(
    caplog, protegrity_developer_python_module, shared_output, docstring
):
    logger = logging.getLogger("protegrity_developer_python")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        shared_output["result"] = protegrity_developer_python_module.find_and_redact(
            docstring.strip()
        )
        if not shared_output["result"]:
            pytest.fail("find_and_redact returned an empty output.")

    shared_output["caplog_warning"] = caplog.text


@then(
    parsers.parse(
        'a warning should be logged about the unsupported method as "{exp_warning_log}"'
    )
)
def verify_warning_log(exp_warning_log, shared_output):
    assert exp_warning_log in shared_output["caplog_warning"]
