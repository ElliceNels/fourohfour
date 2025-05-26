"""This module contains the logger setup function."""

import logging
from src.server.config import config
import os
from pathlib import Path

logger = logging.getLogger(__name__)

def setup_logger():
    """Setup the logger."""
    script_dir = Path(__file__).parent
    filepath = script_dir / config.logging.file_path

    if not filepath.exists():
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.touch(exist_ok=True)

    logging.basicConfig(
        level=config.logging.level, 
        format=config.logging.format, 
        handlers=[
            logging.FileHandler(filepath),
            logging.StreamHandler()
        ])
    logger.info('Logger is setup')
