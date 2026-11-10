"""LogPulse: extract test failures and security warnings from CI/CD logs."""

from .parser import parse_log
from .service import analyze_text, process_blob

__all__ = ["analyze_text", "parse_log", "process_blob"]
__version__ = "0.1.0"
