"""Unit tests for scan module"""

import sys
import types

import pytest
from unittest.mock import patch, Mock

# Stub logger module before importing the package to avoid KeyError during initialization
if "protegrity_developer_python.utils.logger" not in sys.modules:
    logger_module = types.ModuleType("protegrity_developer_python.utils.logger")
    _mock_logger = Mock()

    def _get_logger():
        return _mock_logger

    setattr(logger_module, "get_logger", _get_logger)
    sys.modules["protegrity_developer_python.utils.logger"] = logger_module

from protegrity_developer_python.scan import scan_conversation_messages
from protegrity_developer_python.utils.semantic_guardrails import (
    MessageRiskRequest,
    MessageBatchRiskResponse,
    MessageRiskResponse,
    BatchRiskResponse,
    ProcessorResult,
)


# Sample test data
sample_messages = [
    MessageRiskRequest(
        id="msg1",
        from_="user",
        to="ai",
        content="Hello, how are you?",
        processors=["toxicity"],
    ),
    MessageRiskRequest(
        id="msg2",
        from_="ai",
        to="user",
        content="I'm doing well, thank you!",
        processors=["toxicity"],
    ),
]

mock_approved_response = MessageBatchRiskResponse(
    messages=[
        MessageRiskResponse(
            id="msg1",
            outcome="approved",
            score=0.1,
            processors=[
                ProcessorResult(
                    name="toxicity", score=0.1, explanation="Content is safe"
                )
            ],
        ),
        MessageRiskResponse(
            id="msg2",
            outcome="approved",
            score=0.05,
            processors=[
                ProcessorResult(
                    name="toxicity", score=0.05, explanation="Content is safe"
                )
            ],
        ),
    ],
    batch=BatchRiskResponse(outcome="approved", score=0.075, rejected_messages=[]),
)

mock_rejected_response = MessageBatchRiskResponse(
    messages=[
        MessageRiskResponse(
            id="msg1",
            outcome="rejected",
            score=0.95,
            processors=[
                ProcessorResult(
                    name="toxicity", score=0.95, explanation="Toxic content detected"
                )
            ],
        ),
    ],
    batch=BatchRiskResponse(outcome="rejected", score=0.95, rejected_messages=["msg1"]),
)


def test_scan_conversation_messages_approved():
    """Test scanning messages that are approved"""
    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.return_value = mock_approved_response

        result = scan_conversation_messages(sample_messages)

        assert result.batch.outcome == "approved"
        assert len(result.messages) == 2
        assert result.batch.score == 0.075
        assert len(result.batch.rejected_messages) == 0
        mock_scan_messages.assert_called_once()


def test_scan_conversation_messages_rejected():
    """Test scanning messages that are rejected"""
    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.return_value = mock_rejected_response

        result = scan_conversation_messages([sample_messages[0]])

        assert result.batch.outcome == "rejected"
        assert len(result.messages) == 1
        assert result.messages[0].outcome == "rejected"
        assert result.messages[0].score == 0.95
        assert "msg1" in result.batch.rejected_messages
        mock_scan_messages.assert_called_once()


def test_scan_conversation_messages_with_skipped():
    """Test scanning messages with skipped messages"""
    messages_with_skip = [
        MessageRiskRequest(
            id="msg1",
            from_="user",
            to="ai",
            content="Hello",
            processors=None,  # This will be skipped
        ),
        MessageRiskRequest(
            id="msg2",
            from_="user",
            to="ai",
            content="World",
            processors=["toxicity"],
        ),
    ]

    mock_response = MessageBatchRiskResponse(
        messages=[
            MessageRiskResponse(
                id="msg1", outcome="skipped", score=None, processors=[]
            ),
            MessageRiskResponse(
                id="msg2",
                outcome="approved",
                score=0.1,
                processors=[
                    ProcessorResult(
                        name="toxicity", score=0.1, explanation="Content is safe"
                    )
                ],
            ),
        ],
        batch=BatchRiskResponse(outcome="approved", score=0.1, rejected_messages=[]),
    )

    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.return_value = mock_response

        result = scan_conversation_messages(messages_with_skip)

        assert result.messages[0].outcome == "skipped"
        assert result.messages[0].score is None
        assert result.messages[1].outcome == "approved"
        assert result.batch.outcome == "approved"


def test_scan_conversation_messages_empty_list():
    """Test scanning with empty message list - should raise validation error"""
    with pytest.raises(Exception):
        scan_conversation_messages([])


def test_scan_conversation_messages_exception_handling():
    """Test exception handling in scan_conversation_messages"""
    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.side_effect = Exception("API Error")

        with pytest.raises(Exception) as exc_info:
            scan_conversation_messages(sample_messages)

        assert "API Error" in str(exc_info.value)


def test_scan_conversation_messages_with_multiple_processors():
    """Test scanning messages with multiple processors"""
    message = MessageRiskRequest(
        id="msg1",
        from_="user",
        to="ai",
        content="Test content",
        processors=["toxicity"],
    )

    mock_response = MessageBatchRiskResponse(
        messages=[
            MessageRiskResponse(
                id="msg1",
                outcome="approved",
                score=0.15,
                processors=[
                    ProcessorResult(
                        name="toxicity", score=0.15, explanation="Low toxicity"
                    )
                ],
            )
        ],
        batch=BatchRiskResponse(outcome="approved", score=0.15, rejected_messages=[]),
    )

    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.return_value = mock_response

        result = scan_conversation_messages([message])

        assert len(result.messages[0].processors) == 1
        assert result.messages[0].processors[0].name == "toxicity"


def test_scan_conversation_messages_different_roles():
    """Test scanning messages with different sender/receiver roles"""
    messages = [
        MessageRiskRequest(
            id="msg1",
            from_="user",
            to="ai",
            content="User to AI",
            processors=["toxicity"],
        ),
        MessageRiskRequest(
            id="msg2",
            from_="ai",
            to="user",
            content="AI to user",
            processors=["toxicity"],
        ),
        MessageRiskRequest(
            id="msg3",
            from_="context",
            to="ai",
            content="Context to AI",
            processors=["toxicity"],
        ),
    ]

    mock_response = MessageBatchRiskResponse(
        messages=[
            MessageRiskResponse(
                id="msg1",
                outcome="approved",
                score=0.1,
                processors=[
                    ProcessorResult(name="toxicity", score=0.1, explanation="Safe")
                ],
            ),
            MessageRiskResponse(
                id="msg2",
                outcome="approved",
                score=0.08,
                processors=[
                    ProcessorResult(name="toxicity", score=0.08, explanation="Safe")
                ],
            ),
            MessageRiskResponse(
                id="msg3",
                outcome="approved",
                score=0.05,
                processors=[
                    ProcessorResult(name="toxicity", score=0.05, explanation="Safe")
                ],
            ),
        ],
        batch=BatchRiskResponse(outcome="approved", score=0.077, rejected_messages=[]),
    )

    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.return_value = mock_response

        result = scan_conversation_messages(messages)

        assert len(result.messages) == 3
        assert result.batch.outcome == "approved"


def test_scan_conversation_messages_without_message_id():
    """Test scanning messages without providing message IDs"""
    messages = [
        MessageRiskRequest(
            from_="user",
            to="ai",
            content="Message without ID",
            processors=["toxicity"],
        )
    ]

    mock_response = MessageBatchRiskResponse(
        messages=[
            MessageRiskResponse(
                id="generated-id-1",
                outcome="approved",
                score=0.1,
                processors=[
                    ProcessorResult(name="toxicity", score=0.1, explanation="Safe")
                ],
            )
        ],
        batch=BatchRiskResponse(outcome="approved", score=0.1, rejected_messages=[]),
    )

    with patch("protegrity_developer_python.scan.scan_messages") as mock_scan_messages:
        mock_scan_messages.return_value = mock_response

        result = scan_conversation_messages(messages)

        assert result.messages[0].id == "generated-id-1"
        assert result.batch.outcome == "approved"
