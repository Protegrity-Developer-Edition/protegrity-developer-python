import pytest
import protegrity_developer_python
from unittest.mock import patch

# Sample text and mock classification response
sample_text = "Contact me at john.doe@example.com or call 123-456-7890."
mock_response = {
    "classifications": {
        "EMAIL": [{"location": {"start_index": 14, "end_index": 33}}],
        "PHONE": [{"location": {"start_index": 43, "end_index": 55}}],
    }
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
    assert protegrity_developer_python.securefind._config["method"] == "mask"
    assert protegrity_developer_python.securefind._config["masking_char"] == "#"
    assert protegrity_developer_python.securefind._config["enable_logging"] is True
    assert protegrity_developer_python.securefind._config["log_level"] == "DEBUG"


@patch("protegrity_developer_python.securefind.requests.post")
def test_discover_returns_json(mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_response
    result = protegrity_developer_python.discover(sample_text)
    assert "classifications" in result
    assert "EMAIL" in result["classifications"]


@patch("protegrity_developer_python.securefind.discover", return_value=mock_response)
def test_find_and_redact_redaction(mock_discover):
    protegrity_developer_python.configure(method="redact")
    result = protegrity_developer_python.find_and_redact(sample_text)
    assert "[EMAIL_ADDRESS]" in result
    assert "[PHONE_NUMBER]" in result


@patch("protegrity_developer_python.securefind.discover", return_value=mock_response)
def test_find_and_redact_masking(mock_discover):
    protegrity_developer_python.configure(method="mask", masking_char="#")
    result = protegrity_developer_python.find_and_redact(sample_text)
    assert "[EMAIL_ADDRESS]" not in result
    assert "[PHONE_NUMBER]" not in result
    assert "#################" in result or "############" in result
