"""
Module for discovering PII entities using a discovery API.
"""

from typing import Dict
import json
import requests
from protegrity_developer_python.utils.constants import get_config
from protegrity_developer_python.utils.logger import get_logger


_config = get_config("data-discovery")
# Get logger instance
logger = get_logger()


def discover(text: str) -> Dict:
    """
    Discover PII entities in the input text using the configured REST endpoint.

    Args:
        text (str): Input text to classify.

    Returns:
        dict: Full JSON response from the classification API.
    """
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    params = {"score_threshold": _config["classification_score_threshold"]}

    try:
        response = requests.post(
            _config["endpoint_url"],
            headers=headers,
            data=text.encode("utf-8"),
            params=params,
            timeout=30,
        )
        response.raise_for_status()
        response_json = response.json()
        return response_json.get("classifications", {})
    except requests.exceptions.RequestException as e:
        logger.error("HTTP request failed: %s", e)
        raise
    except json.JSONDecodeError as e:
        logger.error("Failed to decode JSON response: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        raise
