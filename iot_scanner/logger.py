# iot_scanner/logger.py

import logging
import os
from .config import LOG_FILE, LOG_DIR, VERBOSE_CONSOLE_OUTPUT

def setup_logging():
    """
    Configures logging for the IoT Device Scanner.
    Logs to a file and optionally to the console.
    """
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create a logger
    iot_logger = logging.getLogger('iot_scanner')
    iot_logger.setLevel(logging.INFO)
    iot_logger.propagate = False # Prevent messages from being passed to the root logger

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    iot_logger.addHandler(file_handler)

    # Console handler (optional)
    if VERBOSE_CONSOLE_OUTPUT:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
        iot_logger.addHandler(console_handler)

    return iot_logger

# Initialize logger when module is imported
iot_logger = setup_logging()
