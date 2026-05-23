"""Logging setup utilities."""

import logging


def setup_logging(config: dict, name: str = "tunnel") -> logging.Logger:
    log_level = config.get("log_level", "INFO").upper()
    level = getattr(logging, log_level, logging.INFO)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Suppress noisy library logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    return logging.getLogger(name)