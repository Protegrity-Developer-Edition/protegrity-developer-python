"""
Module for scanning conversations for security risks using semantic guardrails
"""

from protegrity_developer_python.utils.logger import get_logger


from protegrity_developer_python.utils.semantic_guardrails import (
    MessageRiskRequest,
    scan_messages,
    MessageBatchRiskResponse,
    MessageBatchRiskRequest,
)

logger = get_logger()


def scan_conversation_messages(
    messages: list[MessageRiskRequest],
) -> MessageBatchRiskResponse:
    """
            Scan a batch of conversation messages for security risks using the Semantic Guardrails API.
            A risk assessment is executed on messages to ensure they are within the boundaries of expected topics and content.
    s
            Args:
                messages (list[MessageRiskRequest]): List of messages to scan.

            Returns:
                MessageBatchRiskResponse: Risk assessment for the batch of messages.
    """
    try:
        request = MessageBatchRiskRequest(messages=messages)
        response = scan_messages(request)
        return response
    except Exception as e:
        logger.error(f"Failed to scan conversation messages: {e}")
        raise
