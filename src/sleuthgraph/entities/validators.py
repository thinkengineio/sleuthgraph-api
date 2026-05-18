"""Entity-level validation helpers.

Provides IDN (Internationalized Domain Name) / Punycode detection so the API
can surface an ``is_idn`` flag on entity responses. The frontend uses this to
render a warning badge without needing its own Punycode detection logic.
"""


def is_idn_domain(label: str) -> bool:
    """Return True if *label* contains IDN / Punycode indicators.

    Detection rules (applied to the lowercased label):
    1. Any DNS label starts with ``xn--`` (ACE prefix = Punycode-encoded).
    2. Any codepoint in the label is outside the ASCII range (> U+007F),
       indicating a Unicode domain that has not been converted to Punycode.

    Returns False for plain ASCII domains (``example.com``).
    """
    if any(ord(ch) > 127 for ch in label):
        return True
    parts = label.lower().split(".")
    return any(part.startswith("xn--") for part in parts)
