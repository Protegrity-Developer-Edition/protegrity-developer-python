"""Unit tests for semantic_guardrails module"""

import sys
import types

import pytest
import json
from unittest.mock import patch, Mock
import requests

# Stub logger module before importing the package to avoid KeyError during initialization
if "protegrity_developer_python.utils.logger" not in sys.modules:
    logger_module = types.ModuleType("protegrity_developer_python.utils.logger")
    _mock_logger = Mock()

    def _get_logger():
        return _mock_logger

    setattr(logger_module, "get_logger", _get_logger)
    sys.modules["protegrity_developer_python.utils.logger"] = logger_module

from protegrity_developer_python.utils.semantic_guardrails import (
    scan_messages,
    list_domain_models,
    MessageBatchRiskRequest,
    MessageBatchRiskResponse,
    MessageRiskRequest,
    MessageRiskResponse,
    BatchRiskResponse,
    ProcessorResult,
    DomainModelResponse,
    APIError,
    SemanticGuardrailsError,
)


# Sample test data
sample_message_request = MessageRiskRequest(
    id="test-msg-1",
    from_="user",
    to="ai",
    content="Hello, this is a test message",
    processors=["customer-support"],
)

sample_batch_request = MessageBatchRiskRequest(messages=[sample_message_request])


def test_message_risk_request_with_all_fields():
    """Test MessageRiskRequest creation with all fields"""
    msg = MessageRiskRequest(
        id="msg1",
        from_="user",
        to="ai",
        content="Test content",
        processors=["customer-support"],
    )
    assert msg.id == "msg1"
    assert msg.from_ == "user"
    assert msg.to == "ai"
    assert msg.content == "Test content"
    assert msg.processors == ["customer-support"]


def test_message_risk_request_without_id():
    """Test MessageRiskRequest creation without ID"""
    msg = MessageRiskRequest(
        from_="ai",
        to="user",
        content="Test",
        processors=["customer-support"],
    )
    assert msg.id is None
    assert msg.from_ == "ai"


def test_message_risk_request_without_processors():
    """Test MessageRiskRequest creation without processors (should be skipped)"""
    msg = MessageRiskRequest(
        id="msg1",
        from_="user",
        to="ai",
        content="Test",
        processors=None,
    )
    assert msg.processors is None


def test_message_risk_request_field_alias():
    """Test that 'from_' field is converted to 'from' in JSON output"""
    msg = MessageRiskRequest(
        from_="user",
        to="ai",
        content="Test",
        processors=["customer-support"],
    )
    # Test that from_ is the internal field name
    assert msg.from_ == "user"

    # Test that model_dump converts from_ to from in JSON output
    dumped = msg.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert "from" in dumped
    assert "from_" not in dumped
    assert dumped["from"] == "user"


def test_message_risk_request_content_validation():
    """Test content length validation"""
    # Valid content
    msg = MessageRiskRequest(
        from_="user",
        to="ai",
        content="Valid content",
        processors=["customer-support"],
    )
    assert msg.content == "Valid content"

    # Empty content should be valid
    msg_empty = MessageRiskRequest(
        from_="user",
        to="ai",
        content="",
        processors=["customer-support"],
    )
    assert msg_empty.content == ""


def test_message_risk_request_max_processors():
    """Test processors list maximum length"""
    # Single processor (should be valid)
    msg = MessageRiskRequest(
        from_="user",
        to="ai",
        content="Test",
        processors=["customer-support"],
    )
    assert len(msg.processors) == 1


def test_message_risk_response_structure():
    """Test MessageRiskResponse structure"""
    response = MessageRiskResponse(
        id="msg1",
        outcome="approved",
        score=0.5,
        processors=[
            ProcessorResult(
                name="customer-support",
                score=0.5,
                explanation="Moderate content",
            )
        ],
    )
    assert response.id == "msg1"
    assert response.outcome == "approved"
    assert response.score == 0.5
    assert len(response.processors) == 1


def test_message_risk_response_skipped():
    """Test MessageRiskResponse for skipped message"""
    response = MessageRiskResponse(
        id="msg1",
        outcome="skipped",
        score=None,
        processors=[],
    )
    assert response.outcome == "skipped"
    assert response.score is None
    assert len(response.processors) == 0


def test_processor_result_structure():
    """Test ProcessorResult structure"""
    processor = ProcessorResult(
        name="customer-support",
        score=0.75,
        explanation="High risk detected",
    )
    assert processor.name == "customer-support"
    assert processor.score == 0.75
    assert processor.explanation == "High risk detected"


def test_processor_result_without_explanation():
    """Test ProcessorResult without explanation"""
    processor = ProcessorResult(
        name="customer-support",
        score=0.2,
    )
    assert processor.name == "customer-support"
    assert processor.score == 0.2
    assert processor.explanation is None


def test_batch_risk_response_approved():
    """Test BatchRiskResponse for approved batch"""
    batch = BatchRiskResponse(
        outcome="approved",
        score=0.3,
        rejected_messages=[],
    )
    assert batch.outcome == "approved"
    assert batch.score == 0.3
    assert len(batch.rejected_messages) == 0


def test_batch_risk_response_rejected():
    """Test BatchRiskResponse for rejected batch"""
    batch = BatchRiskResponse(
        outcome="rejected",
        score=0.85,
        rejected_messages=["msg1", "msg3"],
    )
    assert batch.outcome == "rejected"
    assert batch.score == 0.85
    assert len(batch.rejected_messages) == 2


def test_message_batch_risk_request():
    """Test MessageBatchRiskRequest structure"""
    messages = [
        MessageRiskRequest(
            id="msg1",
            from_="user",
            to="ai",
            content="Test 1",
            processors=["customer-support"],
        ),
        MessageRiskRequest(
            id="msg2",
            from_="ai",
            to="user",
            content="Test 2",
            processors=["customer-support"],
        ),
    ]
    batch_request = MessageBatchRiskRequest(messages=messages)
    assert len(batch_request.messages) == 2


def test_message_batch_risk_response():
    """Test MessageBatchRiskResponse structure"""
    response = MessageBatchRiskResponse(
        messages=[
            MessageRiskResponse(
                id="msg1",
                outcome="approved",
                score=0.2,
                processors=[
                    ProcessorResult(
                        name="customer-support", score=0.2, explanation="Safe"
                    )
                ],
            )
        ],
        batch=BatchRiskResponse(
            outcome="approved",
            score=0.2,
            rejected_messages=[],
        ),
    )
    assert len(response.messages) == 1
    assert response.batch.outcome == "approved"


def test_domain_model_response():
    """Test DomainModelResponse structure"""
    domain_model = DomainModelResponse(
        domain="company.domain",
        model_name="customer_support",
        threshold=0.75,
    )
    assert domain_model.domain == "company.domain"
    assert domain_model.model_name == "customer_support"
    assert domain_model.threshold == 0.75


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_success(mock_post):
    """Test successful message scanning"""
    mock_response_data = {
        "messages": [
            {
                "id": "test-msg-1",
                "outcome": "approved",
                "score": 0.15,
                "processors": [
                    {
                        "name": "customer-support",
                        "score": 0.15,
                        "explanation": "Content is safe",
                    }
                ],
            }
        ],
        "batch": {
            "outcome": "approved",
            "score": 0.15,
            "rejected_messages": [],
        },
    }

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_response_data

    result = scan_messages(sample_batch_request)

    assert isinstance(result, MessageBatchRiskResponse)
    assert len(result.messages) == 1
    assert result.messages[0].id == "test-msg-1"
    assert result.messages[0].outcome == "approved"
    assert result.batch.outcome == "approved"
    mock_post.assert_called_once()


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_rejected(mock_post):
    """Test message scanning with rejected messages"""
    mock_response_data = {
        "messages": [
            {
                "id": "test-msg-1",
                "outcome": "rejected",
                "score": 0.92,
                "processors": [
                    {
                        "name": "customer-support",
                        "score": 0.92,
                        "explanation": "High risk content",
                    }
                ],
            }
        ],
        "batch": {
            "outcome": "rejected",
            "score": 0.92,
            "rejected_messages": ["test-msg-1"],
        },
    }

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_response_data

    result = scan_messages(sample_batch_request)

    assert result.messages[0].outcome == "rejected"
    assert result.batch.outcome == "rejected"
    assert "test-msg-1" in result.batch.rejected_messages


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_http_error(mock_post):
    """Test scan_messages handling HTTP errors"""
    mock_post.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "404 Not Found"
    )

    with pytest.raises(requests.exceptions.HTTPError):
        scan_messages(sample_batch_request)


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_connection_error(mock_post):
    """Test scan_messages handling connection errors"""
    mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")

    with pytest.raises(requests.exceptions.ConnectionError):
        scan_messages(sample_batch_request)


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_json_decode_error(mock_post):
    """Test scan_messages handling JSON decode errors"""
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.side_effect = json.JSONDecodeError(
        "Invalid JSON", "", 0
    )

    with pytest.raises(json.JSONDecodeError):
        scan_messages(sample_batch_request)


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_request_timeout(mock_post):
    """Test scan_messages handling timeout"""
    mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

    with pytest.raises(requests.exceptions.Timeout):
        scan_messages(sample_batch_request)


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_multiple_messages(mock_post):
    """Test scanning multiple messages"""
    messages = [
        MessageRiskRequest(
            id=f"msg{i}",
            from_="user",
            to="ai",
            content=f"Message {i}",
            processors=["customer-support"],
        )
        for i in range(1, 4)
    ]
    batch_request = MessageBatchRiskRequest(messages=messages)

    mock_response_data = {
        "messages": [
            {
                "id": f"msg{i}",
                "outcome": "approved",
                "score": 0.1 * i,
                "processors": [
                    {
                        "name": "customer-support",
                        "score": 0.1 * i,
                        "explanation": "Safe",
                    }
                ],
            }
            for i in range(1, 4)
        ],
        "batch": {
            "outcome": "approved",
            "score": 0.2,
            "rejected_messages": [],
        },
    }

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_response_data

    result = scan_messages(batch_request)

    assert len(result.messages) == 3
    assert result.batch.outcome == "approved"


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.get")
def test_list_domain_models_success(mock_get):
    """Test successful domain models listing"""
    mock_response_data = [
        {
            "domain": "company.domain",
            "model_name": "customer_support",
            "threshold": 0.75,
        },
        {
            "domain": "company.domain",
            "model_name": "internal_chat",
            "threshold": 0.80,
        },
    ]

    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = mock_response_data

    result = list_domain_models()

    assert len(result) == 2
    assert isinstance(result[0], DomainModelResponse)
    assert result[0].domain == "company.domain"
    assert result[0].model_name == "customer_support"
    assert result[0].threshold == 0.75
    mock_get.assert_called_once()


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.get")
def test_list_domain_models_empty_list(mock_get):
    """Test listing domain models when none exist"""
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    result = list_domain_models()

    assert len(result) == 0
    assert isinstance(result, list)


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.get")
def test_list_domain_models_http_error(mock_get):
    """Test list_domain_models handling HTTP errors"""
    mock_get.return_value.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Internal Server Error"
    )

    with pytest.raises(requests.exceptions.HTTPError):
        list_domain_models()


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.get")
def test_list_domain_models_connection_error(mock_get):
    """Test list_domain_models handling connection errors"""
    mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

    with pytest.raises(requests.exceptions.ConnectionError):
        list_domain_models()


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.get")
def test_list_domain_models_json_decode_error(mock_get):
    """Test list_domain_models handling JSON decode errors"""
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

    with pytest.raises(json.JSONDecodeError):
        list_domain_models()


def test_api_error_exception():
    """Test APIError exception"""
    error = APIError("Test error message", status_code=404)
    assert error.message == "Test error message"
    assert error.status_code == 404
    assert "Test error message" in str(error)


def test_api_error_without_status_code():
    """Test APIError exception without status code"""
    error = APIError("Test error")
    assert error.message == "Test error"
    assert error.status_code is None


def test_semantic_guardrails_error():
    """Test SemanticGuardrailsError base exception"""
    error = SemanticGuardrailsError("Base error")
    assert "Base error" in str(error)


def test_message_batch_request_model_dump():
    """Test MessageBatchRiskRequest model serialization"""
    request = MessageBatchRiskRequest(messages=[sample_message_request])
    dumped = request.model_dump(mode="json", by_alias=True, exclude_none=True)

    assert "messages" in dumped
    assert len(dumped["messages"]) == 1
    assert (
        dumped["messages"][0]["from"] == "user"
    )  # Custom model_dump converts from_ to from


def test_sender_role_values():
    """Test valid SenderRole values"""
    valid_roles = ["user", "ai", "context"]
    for role in valid_roles:
        msg = MessageRiskRequest(
            from_=role,
            to="ai",
            content="Test",
            processors=["customer-support"],
        )
        assert msg.from_ == role


def test_risk_outcome_values():
    """Test valid RiskOutcome values"""
    valid_outcomes = ["approved", "rejected", "skipped"]
    for outcome in valid_outcomes:
        response = MessageRiskResponse(
            id="msg1",
            outcome=outcome,
            score=0.5 if outcome != "skipped" else None,
            processors=[],
        )
        assert response.outcome == outcome


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_with_skipped_message(mock_post):
    """Test scanning with skipped messages"""
    mock_response_data = {
        "messages": [
            {
                "id": "msg1",
                "outcome": "skipped",
                "score": None,
                "processors": [],
            },
            {
                "id": "msg2",
                "outcome": "approved",
                "score": 0.2,
                "processors": [
                    {
                        "name": "customer-support",
                        "score": 0.2,
                        "explanation": "Safe",
                    }
                ],
            },
        ],
        "batch": {
            "outcome": "approved",
            "score": 0.2,
            "rejected_messages": [],
        },
    }

    messages = [
        MessageRiskRequest(
            id="msg1",
            from_="user",
            to="ai",
            content="Skipped content",
            processors=None,
        ),
        MessageRiskRequest(
            id="msg2",
            from_="user",
            to="ai",
            content="Processed content",
            processors=["customer-support"],
        ),
    ]

    batch_request = MessageBatchRiskRequest(messages=messages)

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_response_data

    result = scan_messages(batch_request)

    assert result.messages[0].outcome == "skipped"
    assert result.messages[0].score is None
    assert result.messages[1].outcome == "approved"


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.post")
def test_scan_messages_validates_url(mock_post):
    """Test that scan_messages calls the correct endpoint"""
    mock_response_data = {
        "messages": [
            {
                "id": "test-msg-1",
                "outcome": "approved",
                "score": 0.1,
                "processors": [
                    {
                        "name": "customer-support",
                        "score": 0.1,
                        "explanation": "Safe",
                    }
                ],
            }
        ],
        "batch": {
            "outcome": "approved",
            "score": 0.1,
            "rejected_messages": [],
        },
    }

    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = mock_response_data

    scan_messages(sample_batch_request)

    # Verify the correct endpoint was called
    call_args = mock_post.call_args
    assert "/conversations/messages/scan" in call_args[0][0]


@patch("protegrity_developer_python.utils.semantic_guardrails.requests.get")
def test_list_domain_models_validates_url(mock_get):
    """Test that list_domain_models calls the correct endpoint"""
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = []

    list_domain_models()

    # Verify the correct endpoint was called
    call_args = mock_get.call_args
    assert "/domain-models/" in call_args[0][0]
