"""
Module for interfacing with Protegrity's appython Protector for data protection.
"""

from appython import Protector

instance, session = None, None


# Initialize the Protector instance
def _initialize_protector():
    global instance
    instance = Protector()
    return instance


# Get or create a Protector session
def get_protector_session():
    global instance, session
    if instance is None:
        protector = _initialize_protector()
        session = protector.create_session("superuser")
    return session
