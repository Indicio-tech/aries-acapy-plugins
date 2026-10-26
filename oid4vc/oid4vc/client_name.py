"""Verifier name (RFC 7591 client_name) in OID4VP request client_metadata.

The name is self-asserted by the verifier tenant. It is not bound to client_id
or to any certificate, so a wallet should show it as the verifier's claim.
"""

import unicodedata

CLIENT_NAME_MAX_LENGTH = 80

# Unicode general categories refused anywhere in the name: control (Cc),
# format (Cf: zero-width, bidi, soft hyphen, tag characters), surrogate (Cs),
# private use (Co), unassigned (Cn), and line and paragraph separators (Zl, Zp).
# A verifier name is an organisation name shown as identity, so characters
# that are invisible or can reorder the text cost more than they give.
REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

# Characters outside those categories that render blank: variation selectors,
# the combining grapheme joiner, the Hangul fillers and the blank braille
# pattern. Inclusive ranges of code points.
REFUSED_BLANK_RANGES = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x2800, 0x2800),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0xE0100, 0xE01EF),
)


def is_refused_character(char: str) -> bool:
    """Return True if the character may not appear in a client_name."""
    if unicodedata.category(char) in REFUSED_CATEGORIES:
        return True
    code_point = ord(char)
    return any(low <= code_point <= high for low, high in REFUSED_BLANK_RANGES)


def normalize_client_name(value) -> str:
    """Return the trimmed client_name, or raise ValueError if it is not valid.

    A valid client_name is a string (null is refused) with no refused
    character anywhere, checked before trimming, and 1 to 80 code points
    after trimming leading and trailing whitespace.
    """
    if not isinstance(value, str):
        raise ValueError("client_name must be a string")
    if any(is_refused_character(char) for char in value):
        raise ValueError(
            "client_name must not contain control, format, separator,"
            " private-use, unassigned or blank-rendering characters"
        )
    value = value.strip()
    if not 1 <= len(value) <= CLIENT_NAME_MAX_LENGTH:
        raise ValueError(f"client_name must be 1 to {CLIENT_NAME_MAX_LENGTH} characters")
    return value
