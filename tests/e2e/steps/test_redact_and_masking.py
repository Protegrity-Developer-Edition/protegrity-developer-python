import json
import logging
import pytest
from pathlib import Path
from utils.helper import normalize_and_clean
from pytest_bdd import scenarios, given, when, then, parsers

scenarios("../features/redact_and_masking.feature")

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


@when(
    "the user calls the find_and_redact function with the following input text while capturing logs:"
)
def call_redact_and_track_logs(
    caplog, protegrity_developer_python_module, shared_vars, docstring
):
    logger = logging.getLogger("protegrity_developer_python")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        shared_vars["result"] = protegrity_developer_python_module.find_and_redact(
            docstring.strip()
        )
        if not shared_vars["result"]:
            pytest.fail("find_and_redact returned an empty output.")

    shared_vars["caplog_warning"] = caplog.text


@then(
    parsers.parse(
        'a warning should be logged about the unsupported method as "{exp_warning_log}"'
    )
)
def verify_warning_log(exp_warning_log, shared_vars):
    assert exp_warning_log in shared_vars["caplog_warning"]
