"""
Logging configuration utilities for OpenEASD API.

Configures logging with IST timezone timestamps.
"""

import logging
import sys
from datetime import datetime
from src.utils.timezone import IST


class ISTFormatter(logging.Formatter):
    """Custom logging formatter that uses IST timezone."""
    
    def formatTime(self, record, datefmt=None):
        """Format log timestamp in IST."""
        # Convert timestamp to IST datetime
        dt = datetime.fromtimestamp(record.created, tz=IST)
        
        # Use custom format if provided, otherwise use 24-hour format
        if datefmt:
            return dt.strftime(datefmt)
        else:
            return dt.strftime('%Y-%m-%d %H:%M:%S IST')


def setup_logging(log_level: str = "INFO") -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Create custom formatter
    formatter = ISTFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Apply custom formatter to all handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)
    
    # Set specific logger levels
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)