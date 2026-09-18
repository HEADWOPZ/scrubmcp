"""ScrubMCP — local PII scrub + footprint hygiene for agent pipelines.

Never uploads. Never calls a remote LLM. Never logs secrets.
This is not VoiceRail (audio).
"""

from __future__ import annotations

from scrubmcp.engine import Finding, ScrubResult, detect, scrub, scrub_path
from scrubmcp.privacy import NEVER_UPLOADS, assert_local_only

__version__ = "0.1.0"
__author__ = "Kevin Lance Murray (HEADWOPZ)"
__license__ = "MIT"

# Public privacy contract — imported by tests and the README snippet.
LOCAL_ONLY = True
REMOTE_LLM = False

__all__ = [
    "Finding",
    "LOCAL_ONLY",
    "NEVER_UPLOADS",
    "REMOTE_LLM",
    "ScrubResult",
    "assert_local_only",
    "detect",
    "scrub",
    "scrub_path",
    "__version__",
]
