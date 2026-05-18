"""BYOKPlugin — base class for plugins that require user-provided API keys.

Concrete subclasses (VirusTotal, Shodan, HIBP, etc.) set ``credential_name``
and ``credential_url``, then implement ``query()``. The runner checks
``requires_credentials`` and injects the decrypted key before dispatch.
"""

from sleuthgraph.plugins.base import OSINTPlugin


class BYOKPlugin(OSINTPlugin):
    """Plugin that requires a user-provided API key."""

    requires_credentials: bool = True

    # Override in subclass:
    credential_name: str = ""  # e.g. "virustotal", "shodan"
    credential_url: str = ""  # e.g. "https://virustotal.com/api"
