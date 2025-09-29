import pytest
import protegrity_developer_python
from unittest.mock import patch

# Sample text and mock classification response
sample_text = "Contact me at john.doe@example.com or call 123-456-7890."
mock_response = {
    "EMAIL": [{"location": {"start_index": 14, "end_index": 33}}],
    "PHONE": [{"location": {"start_index": 43, "end_index": 55}}],
}


@pytest.fixture(autouse=True)
def reset_config():
    # Reset configuration before each test
    protegrity_developer_python.configure(
        endpoint_url="http://mock-endpoint",
        named_entity_map={"EMAIL": "EMAIL_ADDRESS", "PHONE": "PHONE_NUMBER"},
        masking_char="*",
        classification_score_threshold=0.5,
        method="redact",
        enable_logging=False,
        log_level="INFO",
    )


def test_configure_updates_settings():
    protegrity_developer_python.configure(
        method="mask", masking_char="#", enable_logging=True, log_level="DEBUG"
    )
    from protegrity_developer_python.utils.constants import CONFIG as _config

    assert _config["method"] == "mask"
    assert _config["masking_char"] == "#"
    assert _config["enable_logging"] is True
    assert _config["log_level"] == "DEBUG"


@patch("protegrity_developer_python.utils.discover.requests.post")
def test_discover_returns_json(mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"classifications": mock_response}
    result = protegrity_developer_python.discover(sample_text)
    assert "EMAIL" in result
    assert "PHONE" in result


@patch("protegrity_developer_python.utils.discover.requests.post")
def test_find_and_redact_redaction(mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"classifications": mock_response}
    protegrity_developer_python.configure(method="redact")
    result = protegrity_developer_python.find_and_redact(sample_text)
    assert "[EMAIL_ADDRESS]" in result
    assert "[PHONE_NUMBER]" in result


@patch("protegrity_developer_python.utils.discover.requests.post")
def test_find_and_redact_masking(mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {"classifications": mock_response}
    protegrity_developer_python.configure(method="mask", masking_char="#")
    result = protegrity_developer_python.find_and_redact(sample_text)
    assert "[EMAIL_ADDRESS]" not in result
    assert "[PHONE_NUMBER]" not in result
    assert "#################" in result or "############" in result
    assert "[PHONE_NUMBER]" not in result
    assert "#################" in result or "############" in result
