"""
OSINTRecon - Lightweight OSINT Reconnaissance Framework

A modular, async OSINT reconnaissance framework designed for CTF competitions
and security research.
"""

__version__ = "1.0.0"
__author__ = "kadirou12333"
__license__ = "MIT"

from osintrecon.core.engine import ReconEngine, ReconResult
from osintrecon.core.config import Config

__all__ = ["ReconEngine", "ReconResult", "Config"]
