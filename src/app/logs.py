import logging
import sys


def configure_logging() -> None:
    """Configure stdlib logging so uvicorn and our own logger write to stdout at INFO."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s', datefmt='%H:%M:%S'))
    root.addHandler(handler)
