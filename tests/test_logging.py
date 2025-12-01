
import logging
import time
from datetime import datetime, timezone
import pytest

from src.utils.logging import ISTFormatter, setup_logging, get_logger
from src.utils.timezone import IST


def test_ist_formatter():
    """Test that the ISTFormatter correctly formats log timestamps."""
    formatter = ISTFormatter(fmt='%(asctime)s - %(message)s')
    
    # Create a log record with a known timestamp (in UTC)
    record_time = datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    record = logging.LogRecord(
        name='test_logger',
        level=logging.INFO,
        pathname='test.py',
        lineno=10,
        msg='Test message',
        args=(),
        exc_info=None
    )
    record.created = record_time
    
    # Format the record
    formatted_message = formatter.format(record)
    
    # The expected time is 10:00 UTC, which is 15:30 IST
    expected_timestamp = "2023-01-01 15:30:00 IST"
    assert expected_timestamp in formatted_message
    assert "Test message" in formatted_message

def test_setup_logging(capsys):
    """Test that setup_logging configures the root logger correctly."""
    # Force re-configuration by removing existing handlers before the test
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Setup logging with DEBUG level
    setup_logging(log_level="DEBUG")
    
    # 1. Check if the log level is set correctly
    assert root_logger.level == logging.DEBUG
    
    # 2. Check if the formatter is our custom ISTFormatter
    assert len(root_logger.handlers) > 0
    assert isinstance(root_logger.handlers[0].formatter, ISTFormatter)
    
    # 3. Check if log messages are captured by capturing stdout
    logging.debug("This is a debug message.")
    captured = capsys.readouterr()
    assert "This is a debug message." in captured.out

def test_get_logger(capsys):
    """Test the get_logger utility."""
    # Force re-configuration by removing existing handlers before the test
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Get a new logger
    my_logger = get_logger("my_test_logger")
    my_logger.setLevel(logging.INFO) # Set level for this specific logger
    
    # 1. Check if it's a valid logger instance
    assert isinstance(my_logger, logging.Logger)
    assert my_logger.name == "my_test_logger"
    
    # 2. Check that it has a handler with the correct formatter
    assert len(my_logger.handlers) > 0
    assert isinstance(my_logger.handlers[0].formatter, ISTFormatter)
    
    # 3. Check propagation and log output
    my_logger.info("Hello from my_test_logger")
    captured = capsys.readouterr()
    assert "Hello from my_test_logger" in captured.out

def test_setup_logging_with_get_logger(capsys):
    """Test that get_logger works as expected after setup_logging."""
    # Force re-configuration by removing existing handlers before the test
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    setup_logging(log_level="WARNING")
    
    # Logger retrieved after setup should inherit the root config
    another_logger = get_logger("another_logger")
    
    # The root level is WARNING, so INFO should not be processed
    another_logger.info("This should not appear.")
    captured = capsys.readouterr()
    assert "This should not appear." not in captured.out

    # WARNING message should appear
    another_logger.warning("This should appear.")
    captured = capsys.readouterr()
    assert "This should appear." in captured.out
        
    # Check that the formatter is correct
    assert "IST" in captured.out
    assert "WARNING" in captured.out
