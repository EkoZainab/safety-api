"""Post-match validators for regex rules."""

from __future__ import annotations

from collections.abc import Callable


def luhn_check(text: str) -> bool:
    """Return True if *text* passes the Luhn checksum algorithm.

    Non-digit characters are stripped before validation.
    """
    digits = [int(c) for c in text if c.isdigit()]
    if len(digits) < 2:
        return False

    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


VALIDATOR_REGISTRY: dict[str, Callable[[str], bool]] = {
    "luhn": luhn_check,
}
