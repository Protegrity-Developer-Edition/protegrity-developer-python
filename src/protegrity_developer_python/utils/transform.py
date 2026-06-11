"""
Module for redacting PII entities using the Data Discovery transform/label API.
"""

import json
import requests
from protegrity_developer_python.utils.constants import get_config
from protegrity_developer_python.utils.logger import get_logger
from protegrity_developer_python.utils.pii_processing import redact_data, collect_entity_spans

_config = get_config("data-discovery")
# Get logger instance
logger = get_logger()


def transform_label(text: str) -> str:
    """
    Redact or mask PII entities in the input text using the transform/label API.

    When method is "redact" (default), calls the Data Discovery v2 transform/label
    endpoint and returns the redacted text with [ENTITY_TYPE] labels.

    When method is "mask", uses include_classification_details to get entity
    positions from the same API call and replaces them with the masking_char.

    Args:
        text (str): Input text to redact or mask.

    Returns:
        str: Redacted or masked text.
    """
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    method = _config.get("method", "redact")
    params = {"include_classification_details": "yes"} if method == "mask" else {}

    try:
        response = requests.post(
            _config["transform_url"],
            headers=headers,
            params=params,
            data=text.encode("utf-8"),
            timeout=30,
        )
        response.raise_for_status()
        response_json = response.json()
        logger.debug("Transform/label response: %s", response_json)

        if method == "mask":
            classifications = response_json.get("classifications", {})
            if classifications:
                pii_entity_spans = collect_entity_spans(classifications)
                return redact_data(pii_entity_spans, text)
            logger.info("No PII entities found.")
            return text

        redacted = response_json.get("transform", {}).get("text", text)
        return redacted
    except requests.exceptions.RequestException as e:
        logger.error("HTTP request failed: %s", e)
        raise
    except json.JSONDecodeError as e:
        logger.error("Failed to decode JSON response: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        raise
