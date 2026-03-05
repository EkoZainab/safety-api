"""Tests for post-match validators."""

from __future__ import annotations

import pytest

from safety_api.rules.validators import VALIDATOR_REGISTRY, luhn_check


class TestLuhnCheck:
    @pytest.mark.parametrize(
        "number",
        [
            "4111111111111111",   # Visa test number
            "5500000000000004",   # Mastercard test number
            "378282246310005",    # Amex test number
            "4111-1111-1111-1111",  # with dashes
            "4111 1111 1111 1111",  # with spaces
        ],
    )
    def test_valid_card_numbers(self, number: str) -> None:
        assert luhn_check(number) is True

    @pytest.mark.parametrize(
        "number",
        [
            "1234567890123456",  # arbitrary digits — fails Luhn
            "0000000000000000",  # all zeros pass Luhn, but…
            "1111111111111111",  # fails Luhn
            "1234",             # too short to be a card, but tests algorithm
        ],
    )
    def test_invalid_card_numbers(self, number: str) -> None:
        if number == "0000000000000000":
            # All-zeros technically passes Luhn (sum=0, 0%10==0)
            assert luhn_check(number) is True
            return
        assert luhn_check(number) is False

    def test_single_digit_fails(self) -> None:
        assert luhn_check("5") is False

    def test_empty_string_fails(self) -> None:
        assert luhn_check("") is False

    def test_registry_contains_luhn(self) -> None:
        assert "luhn" in VALIDATOR_REGISTRY
        assert VALIDATOR_REGISTRY["luhn"] is luhn_check
