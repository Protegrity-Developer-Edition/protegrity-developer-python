import pytest
from unittest.mock import patch, MagicMock

import protegrity_developer_python
from protegrity_developer_python.utils.ccn_processing import clean_ccn, reconstruct_ccn
from protegrity_developer_python.utils.pii_processing import (
    _merge_overlapping_entities,
    collect_entity_spans,
    protect_data,
    unprotect_data,
    redact_data,
)
import protegrity_developer_python.securefind as securefind


@pytest.fixture(autouse=True)
def setup_config():
    protegrity_developer_python.configure(
        endpoint_url="http://mock-endpoint",
        named_entity_map={
            "PERSON": "PERSON",
            "CREDIT_CARD": "CREDIT_CARD",
            "EMAIL_ADDRESS": "EMAIL_ADDRESS",
            "PHONE_NUMBER": "PHONE_NUMBER",
        },
        masking_char="*",
        classification_score_threshold=0.5,
        method="redact",
        enable_logging=False,
    )


def test_clean_and_reconstruct_ccn():
    ccn = "1234-5678-9012-3456"
    cleaned, sep_map = clean_ccn(ccn)
    assert cleaned == "1234567890123456"
    assert sep_map == {4: "-", 9: "-", 14: "-"}
    
    restored = reconstruct_ccn(cleaned, sep_map)
    assert restored == ccn


def test_reconstruct_ccn_with_trailing():
    ccn = "1234-5678-"
    cleaned, sep_map = clean_ccn(ccn)
    assert cleaned == "12345678"
    assert reconstruct_ccn(cleaned, sep_map) == ccn


def test_merge_overlapping_entities():
    # Overlapping spans
    spans = {
        (10, 20): ("EMAIL_ADDRESS", 0.9),
        (15, 25): ("PHONE_NUMBER", 0.8),
    }
    merged = _merge_overlapping_entities(spans)
    assert (10, 25) in merged
    assert "EMAIL_ADDRESS|PHONE_NUMBER" in merged[(10, 25)][0]
    assert merged[(10, 25)][1] == 0.9


def test_merge_overlapping_entities_equal_score():
    spans = {
        (0, 10): ("PHONE_NUMBER", 0.8),
        (5, 15): ("EMAIL_ADDRESS", 0.8),
    }
    merged = _merge_overlapping_entities(spans)
    assert (0, 15) in merged
    assert "EMAIL_ADDRESS|PHONE_NUMBER" in merged[(0, 15)][0]


def test_merge_overlapping_entities_same_entity():
    spans = {
        (0, 10): ("EMAIL_ADDRESS", 0.7),
        (5, 15): ("EMAIL_ADDRESS", 0.9),
    }
    merged = _merge_overlapping_entities(spans)
    assert (0, 15) in merged
    assert merged[(0, 15)][0] == "EMAIL_ADDRESS"
    assert merged[(0, 15)][1] == 0.9


def test_collect_entity_spans():
    entities = {
        "EMAIL_ADDRESS": [{"location": {"start_index": 10, "end_index": 20}, "score": 0.95}],
        "PHONE_NUMBER": [{"location": {"start_index": 10, "end_index": 20}, "score": 0.8}],
    }
    collected = collect_entity_spans(entities)
    assert (10, 20) in collected
    assert collected[(10, 20)][0] == "EMAIL_ADDRESS"


@patch("protegrity_developer_python.utils.pii_processing.get_protector_session")
def test_protect_data_standard(mock_session_fn):
    mock_session = MagicMock()
    mock_session.protect.return_value = "PROT_JOHN"
    mock_session_fn.return_value = mock_session

    text = "Hello John, welcome!"
    spans = {(6, 10): ("PERSON", 0.9)}
    result = protect_data(spans, text)
    assert "[PERSON]PROT_JOHN[/PERSON]" in result


@patch("protegrity_developer_python.utils.pii_processing.get_protector_session")
def test_protect_data_ccn(mock_session_fn):
    mock_session = MagicMock()
    mock_session.protect.return_value = "9876543210987654"
    mock_session_fn.return_value = mock_session

    text = "Card: 1234-5678-9012-3456"
    spans = {(6, 25): ("CREDIT_CARD", 0.99)}
    result = protect_data(spans, text)
    assert "[CREDIT_CARD]9876-5432-1098-7654[/CREDIT_CARD]" in result


@patch("protegrity_developer_python.utils.pii_processing.get_protector_session")
def test_protect_data_failure_fallback(mock_session_fn):
    mock_session = MagicMock()
    mock_session.protect.side_effect = Exception("Protect failed")
    mock_session_fn.return_value = mock_session

    text = "Hello John, welcome!"
    spans = {(6, 10): ("PERSON", 0.9)}
    result = protect_data(spans, text)
    assert result == text


@patch("protegrity_developer_python.utils.pii_processing.get_protector_session")
def test_unprotect_data_standard(mock_session_fn):
    mock_session = MagicMock()
    mock_session.unprotect.return_value = "john.doe@example.com"
    mock_session_fn.return_value = mock_session

    text = "Email: [EMAIL_ADDRESS]protected_email[/EMAIL_ADDRESS]"
    result = unprotect_data(text)
    assert result == "Email: john.doe@example.com"


@patch("protegrity_developer_python.utils.pii_processing.get_protector_session")
def test_unprotect_data_ccn(mock_session_fn):
    mock_session = MagicMock()
    mock_session.unprotect.return_value = "1234567890123456"
    mock_session_fn.return_value = mock_session

    text = "Card: [CREDIT_CARD]9876-5432-1098-7654[/CREDIT_CARD]"
    result = unprotect_data(text)
    assert result == "Card: 1234-5678-9012-3456"


@patch("protegrity_developer_python.utils.pii_processing.get_protector_session")
def test_unprotect_data_failure_fallback(mock_session_fn):
    mock_session = MagicMock()
    mock_session.unprotect.side_effect = Exception("Unprotect failed")
    mock_session_fn.return_value = mock_session

    text = "Email: [EMAIL_ADDRESS]protected_email[/EMAIL_ADDRESS]"
    result = unprotect_data(text)
    assert result == "Email: protected_email"


def test_redact_data_single_and_split():
    text = "Contact 1234567890 today."
    spans = {(8, 18): ("PHONE_NUMBER", 0.95)}
    res = redact_data(spans, text)
    assert "[PHONE_NUMBER]" in res


@patch("protegrity_developer_python.securefind.discover")
@patch("protegrity_developer_python.securefind.protect_data")
def test_find_and_protect(mock_protect_data, mock_discover):
    mock_discover.return_value = {
        "EMAIL_ADDRESS": [{"location": {"start_index": 5, "end_index": 15}, "score": 0.9}]
    }
    mock_protect_data.return_value = "Protected text"
    res = securefind.find_and_protect("test email")
    assert res == "Protected text"


@patch("protegrity_developer_python.securefind.discover")
def test_find_and_protect_no_pii(mock_discover):
    mock_discover.return_value = {}
    res = securefind.find_and_protect("clean text")
    assert res == "clean text"


@patch("protegrity_developer_python.securefind.unprotect_data")
def test_find_and_unprotect(mock_unprotect_data):
    mock_unprotect_data.return_value = "unprotected text"
    res = securefind.find_and_unprotect("protected text")
    assert res == "unprotected text"
