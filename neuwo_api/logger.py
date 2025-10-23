"""
Logging configuration for the Neuwo API SDK.

This module provides a centralized logging setup for the SDK.
"""

import logging
from typing import Optional

# Default logger name
LOGGER_NAME = "neuwo_api"


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a logger instance for the Neuwo API SDK.

    Args:
        name: Optional name for the logger. If not provided, uses default.

    Returns:
        Configured logger instance
    """
    logger_name = f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME
    return logging.getLogger(logger_name)


def setup_logger(
    level: int = logging.WARNING,
    format_string: Optional[str] = None,
    handler: Optional[logging.Handler] = None,
) -> logging.Logger:
    """Setup and configure the Neuwo API logger.

    This function configures the root logger for the SDK. By default,
    only warnings and errors are logged. Set level to logging.DEBUG
    to see detailed API request/response information.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO)
        format_string: Custom format string for log messages
        handler: Custom handler. If not provided, uses StreamHandler

    Returns:
        Configured logger instance

    Example:
        >>> from neuwo_api.logger import setup_logger
        >>> import logging
        >>>
        >>> # Enable debug logging to see all API calls
        >>> setup_logger(level=logging.DEBUG)
        >>>
        >>> # Or use INFO level for less verbose output
        >>> setup_logger(level=logging.INFO)
    """
    logger = get_logger()

    # Avoid adding multiple handlers if called multiple times
    if logger.handlers:
        logger.handlers.clear()

    # Set level
    logger.setLevel(level)

    # Create handler
    if handler is None:
        handler = logging.StreamHandler()
        handler.setLevel(level)

    # Create formatter
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(format_string)
    handler.setFormatter(formatter)

    # Add handler to logger
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def disable_logger():
    """Disable all logging from the Neuwo API SDK.

    Example:
        >>> from neuwo_api.logger import disable_logger
        >>> disable_logger()
    """
    logger = get_logger()
    logger.disabled = True
    logger.propagate = False


def enable_logger(level: int = logging.WARNING):
    """Re-enable logging after it was disabled.

    Args:
        level: Logging level to set

    Example:
        >>> from neuwo_api.logger import enable_logger
        >>> import logging
        >>> enable_logger(level=logging.INFO)
    """
    logger = get_logger()
    logger.disabled = False
    logger.setLevel(level)


# Default logger instance
logger = get_logger()
