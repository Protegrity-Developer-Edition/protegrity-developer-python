"""
Module for discovering and redacting or masking PII entities in text.
"""

import os
import json
import logging
from typing import Dict, Optional, Tuple
import requests


# Default configuration
_config = {
    "endpoint_url": os.getenv(
        "DISCOVER_URL", "http://localhost:8580/pty/data-discovery/v1.0/classify"
    ),
    "named_entity_map": {},
    "masking_char": "#",
    "classification_score_threshold": 0.6,
    "method": "redact",  # or "mask"
    "enable_logging": True,
    "log_level": "INFO",
}

# Configure logger
logger = logging.getLogger("protegrity_developer_python")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

if _config["enable_logging"]:
    level = getattr(logging, _config["log_level"].upper(), logging.INFO)
    logger.setLevel(level)
    logger.propagate = False
else:
    logger.disabled = True


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
    if endpoint_url:
        _config["endpoint_url"] = endpoint_url
    if named_entity_map:
        _config["named_entity_map"] = named_entity_map
    if masking_char:
        _config["masking_char"] = masking_char
    if classification_score_threshold is not None:
        _config["classification_score_threshold"] = classification_score_threshold
    if method in ("redact", "mask"):
        _config["method"] = method
    elif method:
        logger.warning(
            "Invalid method specified: %s. Must be 'redact' or 'mask'.", method
        )
    if enable_logging is not None:
        _config["enable_logging"] = enable_logging
        logger.disabled = not enable_logging
    if log_level:
        _config["log_level"] = log_level
        level = getattr(logging, log_level.upper(), logging.INFO)
        logger.setLevel(level)


def discover(text: str) -> Dict:
    """
    Discover PII entities in the input text using the configured REST endpoint.

    Args:
        text (str): Input text to classify.

    Returns:
        dict: Full JSON response from the classification API.
    """
    headers = {"Content-Type": "text/plain"}
    params = {"score_threshold": _config["classification_score_threshold"]}

    try:
        response = requests.post(
            _config["endpoint_url"],
            headers=headers,
            data=text,
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error("HTTP request failed: %s", e)
        raise
    except json.JSONDecodeError as e:
        logger.error("Failed to decode JSON response: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        raise


def _collect_entity_spans(entities: Dict) -> Dict[Tuple[int, int], Tuple[str, float]]:
    """
    Collects entity spans for redaction or masking based on score.

    Returns a dictionary of (start_index, end_index) : (entity_name, score).
    The dictionary is sorted in reverse order of start_index to ensure that replacements
    do not affect the character positions of subsequent spans.

    Args:
        entities (dict): Dictionary of detected PII entities.

    Returns:
        dict: Sorted entity spans mapped to entity names and scores.
    """
    entity_map = {}
    for entity_name, entity_details in entities.items():
        for obj in entity_details:
            score = obj.get("score")
            loc = obj.get("location", {})
            start = loc.get("start_index", 0)
            end = loc.get("end_index", 0)
            if (start, end) in entity_map:
                if score > entity_map[(start, end)][1]:
                    entity_map[(start, end)] = (entity_name, score)
            else:
                entity_map[(start, end)] = (entity_name, score)
    # Sort entity_map in reverse order of start index to avoid index shifting
    return {
        key: entity_map[key]
        for key in sorted(entity_map, key=lambda x: x[0], reverse=True)
    }


def _merge_overlapping_entities(
    entity_spans: Dict[Tuple[int, int], Tuple[str, float]],
) -> Dict[Tuple[int, int], Tuple[str, float]]:
    """
    Merge overlapping entity spans in a dictionary.

    Given a dictionary with (start, end) index tuples as keys and (entity, score) tuples as values,
    this function merges overlapping or adjacent spans by combining entity labels with '|' and
    retaining the highest score.

    Args:
        entity_dict (dict): Mapping of index spans to (entity, score).

    Returns:
        dict: Merged spans with combined entities and max scores.

    Example:
        Input:
            {
                (10, 20): ("PERSON", 0.9),
                (15, 25): ("LOCATION", 0.85)
            }
        Output:
            {
                (10, 25): ("PERSON|LOCATION", 0.9)
            }
    """
    merged = []
    for (start, end), (entity, score) in entity_spans.items():
        if not merged:
            merged.append([(start, end), entity, score])
        else:
            last_start, last_end = merged[-1][0]
            # Check for overlap
            if start <= last_end and end >= last_start:
                # Merge ranges
                new_start = min(start, last_start)
                new_end = max(end, last_end)
                # Merge entities
                if entity != merged[-1][1]:
                    new_entity = merged[-1][1] + "|" + entity
                else:
                    new_entity = entity
                # Take max score
                new_score = max(score, merged[-1][2])
                merged[-1] = [(new_start, new_end), new_entity, new_score]
            else:
                merged.append([(start, end), entity, score])

    # Convert back to dictionary
    return {tuple(k): (v, s) for k, v, s in merged}


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
        response_json = discover(text)
        entities = response_json.get("classifications", {})
        if not entities:
            logger.info("No PII entities found.")
            return text

        entity_spans = _collect_entity_spans(entities)
        logger.debug("Raw Entity spans collected: \n%s", entity_spans)
        merged_entities = _merge_overlapping_entities(entity_spans)
        logger.debug("Merged Entity spans: \n%s", merged_entities)
        for key, val in merged_entities.items():
            start, end = key
            entity_name = val[0]
            logger.debug(
                "Entity '%s' found at span [%d:%d] with score %f",
                entity_name,
                start,
                end,
                val[1],
            )
            if _config["method"] == "redact":
                if "|" in entity_name:
                    label = "|".join(
                        _config["named_entity_map"].get(entity, entity)
                        for entity in entity_name.split()
                    )
                else:
                    label = _config["named_entity_map"].get(entity_name, "")
                if label:
                    label = f"[{label}]"
                    logger.info(
                        "Entity '%s' found at span [%d:%d]... redacted as %s",
                        entity_name,
                        start,
                        end,
                        label,
                    )
                else:
                    label = f"[{entity_name}]"
                    logger.warning(
                        "Entity '%s' found at span [%d:%d], but not mapped... redact as %s itself",
                        entity_name,
                        start,
                        end,
                        label,
                    )
                text = text[:start] + label + text[end:]
            elif _config["method"] == "mask":
                logger.info(
                    "Entity '%s' found at span [%d:%d]... masked",
                    entity_name,
                    start,
                    end,
                )
                text = (
                    text[:start] + _config["masking_char"] * (end - start) + text[end:]
                )

        return text
    except Exception as e:
        logger.error("Failed to process text: %s", e)
        raise
