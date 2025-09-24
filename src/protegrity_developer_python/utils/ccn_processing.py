"""
Module for processing credit card numbers (CCNs) by removing and reconstructing separators.
"""


def clean_ccn(ccn_string: str) -> tuple[str, dict]:
    """
    Remove separators from credit card number and store their positions.

    Args:
        ccn_string (str): Credit card number with separators

    Returns:
        tuple: (cleaned_string, separator_map)
            - cleaned_string: CCN with only digits
            - separator_map: {position: separator_char}
    """
    cleaned = ""
    separator_map = {}

    for i, char in enumerate(ccn_string):
        if char.isdigit():
            cleaned += char
        else:
            # Store the original position and the separator character
            separator_map[i] = char

    return cleaned, separator_map


def reconstruct_ccn(cleaned_ccn: str, separator_map: dict) -> str:
    """
    Reconstruct original CCN format using the separator map.

    Args:
        cleaned_ccn (str): CCN with only digits
        separator_map (dict): {position: separator_char} mapping

    Returns:
        str: CCN with separators restored to original positions
    """
    result = ""
    original_pos = 0

    for cleaned_pos, digit in enumerate(cleaned_ccn):
        # Add any separators that should come before this digit
        while original_pos in separator_map:
            result += separator_map[original_pos]
            original_pos += 1

        result += digit
        original_pos += 1

    # Add any trailing separators
    while original_pos in separator_map:
        result += separator_map[original_pos]
        original_pos += 1

    return result
