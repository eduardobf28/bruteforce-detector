"""Detector de brute force em logs de autenticacao."""

__version__ = "0.1.0"

from .detection import Alert, Detector, Thresholds
from .parsers import LoginEvent, parse_lines

__all__ = ["Alert", "Detector", "LoginEvent", "Thresholds", "__version__", "parse_lines"]
