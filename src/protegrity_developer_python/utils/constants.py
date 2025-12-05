"""
Module for constants and default configurations.
"""

import os

# Mapping of entity types to Protegrity data elements
DATA_ELEMENT_MAPPING = {
    # Account Information
    "ACCOUNT_NAME": "string",
    "ACCOUNT_NUMBER": "number",
    
    # Personal Information
    "AGE": "number",
    "GENDER": "string",
    "TITLE": "string",
    "PERSON": "string",
    
    # Financial
    "AMOUNT": "number",
    "BANK_ACCOUNT": "number",
    "CREDIT_CARD": "ccn",
    "CURRENCY": "string",
    "CURRENCY_CODE": "string",
    "CURRENCY_NAME": "string",
    "CURRENCY_SYMBOL": "string",
    
    # Cryptocurrency
    "CRYPTO_ADDRESS": "address",
    
    # Temporal
    "DATETIME": "datetime",
    "DOB": "datetime",
    
    # Identification Documents
    "DRIVER_LICENSE": "number",
    "PASSPORT": "passport",
    "NATIONAL_ID": "nin",
    "SOCIAL_SECURITY_ID": "ssn",
    
    # Contact Information
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    
    # Healthcare
    "HEALTH_CARE_ID": "number",
    
    # Location Information
    "LOCATION": "address",
    "ADDRESS": "address",
    
    # Network
    "IP_ADDRESS": "address",
    "MAC_ADDRESS": "address",
    "URL": "address",
    
    # Tax
    "TAX_ID": "number",
    
    # India-specific
    "IN_VEHICLE_REGISTRATION": "number",
    "IN_VOTER": "number",
    "IN_GSTIN": "string",
    
    # Security
    "PASSWORD": "string",
    "USERNAME": "string",
    
    # Organization
    "ORGANIZATION": "string",
    
    # National Registration
    "NRP": "number",
    
    # Korea
    "KR_RRN": "number",
    
    # Thailand
    "TH_TNIN": "nin",
}

CONFIG = {
    "enable_logging": True,
    "log_level": "INFO",
    "data-discovery": {
        "endpoint_url": os.getenv(
            "DISCOVER_URL", "http://localhost:8580/pty/data-discovery/v1.1/classify"
        ),
        "named_entity_map": {},
        "masking_char": "#",
        "classification_score_threshold": 0.6,
        "method": "redact",  # or "mask"
    },
    "semantic-guardrails": {
        "endpoint_url": os.getenv(
            "SEMANTIC_GUARDRAILS_URL",
            "http://localhost:8001/pty/semantic-guardrail/v1.1",
        ),
    },
}


def get_config(section: str = None) -> dict:
    """
    Get configuration for a specific section or the entire config.
    
    Args:
        section (str, optional): Section name ('data-discovery', 'semantic-guardrails'). 
                                If None, returns root config.
    
    Returns:
        dict: Configuration dictionary for the requested section.
    
    Example:
        >>> config = get_config('data-discovery')
        >>> method = config['method']
    """
    if section and section in CONFIG:
        return CONFIG[section]
    return CONFIG
