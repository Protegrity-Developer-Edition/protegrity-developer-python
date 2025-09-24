"""
Module for discovering and redacting, masking or protecting PII entities in text.
"""

from protegrity_developer_python.utils.logger import get_logger
from protegrity_developer_python.utils.discover import discover
from protegrity_developer_python.utils.pii_processing import (
    protect_data,
    unprotect_data,
    redact_data,
    collect_entity_spans,
)

# Get logger instance
logger = get_logger()


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
        if pii_entities:
            pii_entity_spans = collect_entity_spans(pii_entities)
            return protect_data(pii_entity_spans, text)
        logger.info("No PII entities found.")
        return text
    except Exception as e:
        logger.error("Failed to process text: %s", e)
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
        logger.error("Failed to process text: %s", e)
        raise

def find_and_redact(text: str) -> str:
    """
    Redact or mask PII entities in the input text.

    Uses index-based slicing to ensure precise replacement of PII entities
    at known character positions. This avoids accidental replacement of repeated
    entities and ensures correctness when multiple PII spans are present.

    Args:
        text (str): Input text to process.

    Returns:
        str: Redacted or masked text.
    """
    try:
        pii_entities = discover(text)
        if pii_entities:
            pii_entity_spans = collect_entity_spans(pii_entities)
            return redact_data(pii_entity_spans, text)
        logger.info("No PII entities found.")
        return text

    except Exception as e:
        logger.error("Failed to process text: %s", e)
        raise
