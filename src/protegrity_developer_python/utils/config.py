"""
Module for
"""

from protegrity_developer_python.utils.constants import CONFIG as _root_config, get_config
from typing import Dict, Optional
from protegrity_developer_python.utils.logger import get_logger
import logging

# Get logger instance
logger = get_logger()


def configure(
    endpoint_url: Optional[str] = None,
    named_entity_map: Optional[Dict[str, str]] = None,
    masking_char: Optional[str] = None,
    classification_score_threshold: Optional[float] = None,
    method: Optional[str] = None,
    enable_logging: Optional[bool] = None,
    log_level: Optional[str] = None,
) -> None:
    """
    Configure the protegrity_developer_python module.

    Args:
        endpoint_url (str): URL of the discovery classification API.
        named_entity_map (dict): Mapping of entity types to labels.
        masking_char (str): Character used for masking PII.
        classification_score_threshold (float): Minimum score to consider classification.
        method (str): Either 'redact' or 'mask'.
        enable_logging (bool): Enable or disable logging.
        log_level (str): Set the logging level.
    """

    # Configure data-discovery settings
    dd_config = get_config("data-discovery")
    if endpoint_url:
        dd_config["endpoint_url"] = endpoint_url
    if named_entity_map:
        dd_config["named_entity_map"] = named_entity_map
    if masking_char:
        dd_config["masking_char"] = masking_char
    if classification_score_threshold is not None:
        dd_config["classification_score_threshold"] = classification_score_threshold
    if method in ("redact", "mask"):
        dd_config["method"] = method
    elif method:
        logger.warning(
            "Invalid method specified: %s. Must be 'redact' or 'mask'.", method
        )
    
    # Configure global logging settings
    if enable_logging is not None:
        _root_config["enable_logging"] = enable_logging
        logger.disabled = not enable_logging
    if log_level:
        _root_config["log_level"] = log_level
        level = getattr(logging, log_level.upper(), logging.INFO)
        logger.setLevel(level)
