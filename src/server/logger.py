"""This module contains the logger setup function."""

import logging
from config import config
import os
from pathlib import Path

logger = logging.getLogger(__name__)

def setup_logger():
    """Setup the logger."""
    script_dir = Path(__file__).parent
    filepath = script_dir / config.logging.file_path

    if not os.path.exists(filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            pass

    logging.basicConfig(
        level=config.logging.level, 
        format=config.logging.format, 
        handlers=[
            logging.FileHandler(filepath),
            logging.StreamHandler()
        ])
    logger.info('Logger is setup')
