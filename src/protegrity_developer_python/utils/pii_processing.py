"""
Module for processing PII entities in text, including redaction, masking, and protection.
"""

import re
from typing import Dict, Tuple
from protegrity_developer_python.utils.ccn_processing import clean_ccn, reconstruct_ccn
from protegrity_developer_python.utils.protector import get_protector_session
from protegrity_developer_python.utils.logger import get_logger
from protegrity_developer_python.utils.constants import (
    DATA_ELEMENT_MAPPING as entity_endpoint_mapped,
    CONFIG as _config,
)

# Get logger instance
logger = get_logger()


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
    merged_entities = {tuple(k): (v, s) for k, v, s in merged}
    logger.debug("Merged Entity spans: \n%s", merged_entities)
    return merged_entities


def collect_entity_spans(entities: Dict) -> Dict[Tuple[int, int], Tuple[str, float]]:
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
    entity_spans = {
        key: entity_map[key]
        for key in sorted(entity_map, key=lambda x: x[0], reverse=True)
    }

    logger.debug("Raw Entity spans collected: \n%s", entity_spans)
    return _merge_overlapping_entities(entity_spans)

def unprotect_data(text: str) -> str:
    session = get_protector_session()
    try:
        # Regex pattern to match [entity]data[/entity]
        pattern = r'\[([^\]]+)\]([^[]*)\[\/\1\]'
        
        def replace_protected_data(match):
            data_element = entity_endpoint_mapped[match.group(1)] 
            entity = match.group(1)
            data = match.group(2)
            try:
                unprotect_dataprotected = ""
                if entity == "CREDIT_CARD":
                    input_data, separator_map = clean_ccn(data)
                    unprotect_dataprotected = session.unprotect(input_data, data_element)
                    unprotect_dataprotected = reconstruct_ccn(unprotect_dataprotected, separator_map)
                else:
                    unprotect_dataprotected = session.unprotect(data, data_element)
                logger.info(f"Unprotected {data_element}: {data}")
                return unprotect_dataprotected  # Return just the data, removing the tags
            except Exception:
                logger.warning(f"Failed to unprotect {data_element}: {data}.")
                return data  # Return original data if unprotection fails
        
        # Replace all matches with unprotected data
        result = re.sub(pattern, replace_protected_data, text)
        return result
    except Exception as e:
        logger.error("Failed to process text: %s", e)
        raise

def protect_data(
    merged_entities: Dict[Tuple[int, int], Tuple[str, float]], text: str
) -> str:
    """
    Protects the identified PII entities in the input text.

    Args:
        entities (dict): Dictionary of detected PII entities.
        text (str): Original input text.

    Returns:
        text (str): Protected PII text.
    """
    session = get_protector_session()
    for key, val in merged_entities.items():
        start, end = key
        entity, _ = val
        data_element = None
        protected = ""
        get_named_entity_map = None
        entity_selected = None

        if "|" in entity:
            data_element = entity_endpoint_mapped[entity.split("|")[0]]
            entity_selected = entity.split("|")[0]
            get_named_entity_map = _config["named_entity_map"].get(entity.split("|")[0], None)
        else:
            data_element = entity_endpoint_mapped[entity]
            entity_selected = entity
            get_named_entity_map = _config["named_entity_map"].get(entity, None)
        input_data = text[start:end]

        if get_named_entity_map:
            try:
                if entity == "CREDIT_CARD":
                    input_data, separator_map = clean_ccn(input_data)
                    protected = session.protect(input_data, data_element)
                    protected = reconstruct_ccn(protected, separator_map)
                else:
                    protected = session.protect(input_data, data_element)

                logger.info(
                    "Entity '%s' at span [%d:%d] protected successfully.",
                    entity,
                    start,
                    end,
                )

                text = text[:start] + f"[{entity_selected}]" + protected + f"[/{entity_selected}]" + text[end:]
            except Exception:
                logger.warning(
                    "Failed to protect entity '%s' at span [%d:%d] having value %s.",
                    entity,
                    start,
                    end,
                    input_data,
                )
                text = text[:start] + input_data + text[end:]
        else:
            logger.warning(
                "Entity '%s' detected at span [%d:%d] but no mapping found in named_entity_map - skipping protection",
                entity,
                start,
                end,
            )

    return text


def redact_data(
    merged_entities: Dict[Tuple[int, int], Tuple[str, float]], text: str
) -> str:
    """
    Redacts the identified PII entities in the input text.

    Args:
        entities (dict): Dictionary of detected PII entities.
        text (str): Original input text.

    Returns:
        text (str): Redacted PII text.
    """
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
                text = text[:start] + label + text[end:]
            else:
                label = f"[{entity_name}]"
                logger.warning(
                    "Entity '%s' detected at span [%d:%d] but no mapping found in named_entity_map - skipping redaction",
                    entity_name,
                    start,
                    end,
                )
        elif _config["method"] == "mask":
            logger.info(
                "Entity '%s' found at span [%d:%d]... masked",
                entity_name,
                start,
                end,
            )
            text = text[:start] + _config["masking_char"] * (end - start) + text[end:]

    return text
