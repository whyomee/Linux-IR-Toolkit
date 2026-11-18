"""Linux-IR-Toolkit: modular, read-only Linux incident response and forensics.

The package is intentionally side-effect free on import.  Collectors never
modify the system under investigation; they only read files, kernel interfaces
and (optionally) invoke a small allow-list of read-only utilities.
"""

from __future__ import annotations

from irkit.config import TOOL_NAME, TOOL_VERSION

__all__ = ["TOOL_NAME", "TOOL_VERSION", "__version__"]

__version__ = TOOL_VERSION
