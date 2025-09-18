"""
Module for  logging configuration and logger retrieval.
"""

import logging
from protegrity_developer_python.utils.constants import CONFIG as _config

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


def get_logger():
    return logger
