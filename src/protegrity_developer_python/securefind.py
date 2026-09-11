"""
Module for discovering and redacting, masking or protecting PII entities in text.
"""

from protegrity_developer_python.utils.logger import get_logger
from protegrity_developer_python.utils.discover import discover
from protegrity_developer_python.utils.transform import transform_label
from protegrity_developer_python.utils.constants import get_config
from protegrity_developer_python.utils.pii_processing import (
    collect_entity_spans,
    protect_data,
    unprotect_data,
)

# Get logger instance
logger = get_logger()

_LOG_ERR_PROCESS_TEXT = "Failed to process text: %s"


def find_and_protect(text: str) -> str:
    """
    Protect (tokenize) PII entities in the input text.
    Uses index-based slicing to ensure precise replacement of PII entities
    at known character positions. This avoids accidental replacement of repeated
    entities and ensures correctness when multiple PII spans are present.

    Args:
        text (str): Input text to process.

    Returns:
        str: Protected text.
    """
    try:
        pii_entities = discover(text)
        logger.debug("Discovered PII entities: %s", pii_entities)
        if pii_entities:
            pii_entity_spans = collect_entity_spans(pii_entities)
            return protect_data(pii_entity_spans, text)
        logger.info("No PII entities found.")
        return text
    except Exception as e:
        logger.error(_LOG_ERR_PROCESS_TEXT, e)
        raise

def find_and_unprotect(text: str) -> str:
    """
    Unprotect (detokenize) to get PII entities.
    Uses index-based slicing to ensure precise replacement of detokenized PII entities
    at known character positions.

    Args:
        text (str): Input text to process.

    Returns:
        str: Unprotected text.
    """
    try:
        return unprotect_data(text)
    except Exception as e:
        logger.error(_LOG_ERR_PROCESS_TEXT, e)
        raise

def find_and_redact(text: str) -> str:
    """
    Redact or mask PII entities in the input text.

    When method is "redact" (default), calls the Data Discovery v2 transform/label
    endpoint which discovers PII and returns the redacted text in a single request,
    replacing sensitive values with [ENTITY_TYPE] labels.

    When method is "mask", uses the discover API to find PII entities and masks
    them with the configured masking_char.

    Args:
        text (str): Input text to process.

    Returns:
        str: Redacted or masked text.
    """
    try:
        return transform_label(text)
    except Exception as e:
        logger.error(_LOG_ERR_PROCESS_TEXT, e)
        raise
