"""Logging setup utilities."""

import logging


def setup_logging(config: dict, name: str = "tunnel") -> logging.Logger:
    """Setup logging based on configuration.
    
    Args:
        config: Configuration dictionary with optional 'log_level' key.
        name: Logger name.
        
    Returns:
        Configured logger instance.
    """
    log_level = config.get("log_level", "INFO").upper()
    level = getattr(logging, log_level, logging.INFO)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger(name)
