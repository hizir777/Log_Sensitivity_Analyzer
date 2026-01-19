"""
Credit Card Number Validator Module using Luhn Algorithm.

This module provides mathematical validation for credit card numbers
using the Luhn Algorithm (Mod 10 checksum) to distinguish valid card
numbers from random numeric strings.

Author: Senior Python Security Developer
Compliance: PCI DSS, KVKK/GDPR Data Leakage Prevention Standards
"""


def _sanitize_card_number(card_number: str) -> str:
    """
    Sanitize credit card input by removing common separators.

    Args:
        card_number (str): Raw card number input string.

    Returns:
        str: Sanitized numeric string with spaces and hyphens removed.

    Examples:
        >>> _sanitize_card_number("4111 1111 1111 1111")
        '4111111111111111'
        >>> _sanitize_card_number("4111-1111-1111-1111")
        '4111111111111111'
    """
    return card_number.replace(" ", "").replace("-", "")


def validate_luhn(card_number: str) -> bool:
    """
    Validate credit card number using the Luhn Algorithm (Mod 10).

    The Luhn algorithm works as follows:
    1. Starting from the rightmost digit (check digit), move left
    2. Double every second digit
    3. If doubling results in a number > 9, subtract 9
    4. Sum all digits (doubled and non-doubled)
    5. If total modulo 10 equals 0, the number is valid

    Args:
        card_number (str): Credit card number as string (13-19 digits typical).

    Returns:
        bool: True if card number passes Luhn validation, False otherwise.

    Raises:
        None: Function returns False for all invalid inputs.

    Examples:
        >>> validate_luhn("4111111111111111")  # Valid Visa test card
        True
        >>> validate_luhn("4111111111111112")  # Invalid checksum
        False
        >>> validate_luhn("5500 0000 0000 0004")  # Valid MasterCard (with spaces)
        True

    Algorithm Reference:
        ISO/IEC 7812-1 - Identification cards - Numbering system
        https://en.wikipedia.org/wiki/Luhn_algorithm
    """
    # Sanitize input
    card_number = _sanitize_card_number(card_number)

    # Basic validation: must be between 13-19 digits (typical card length)
    if not (13 <= len(card_number) <= 19):
        return False

    # Check if all characters are digits
    if not card_number.isdigit():
        return False

    # Reject all-zeros (edge case: mathematically valid but not a real card)
    if card_number == "0" * len(card_number):
        return False

    # Convert to list of integers
    digits = [int(d) for d in card_number]

    # Luhn algorithm implementation
    checksum = 0

    # Process digits from right to left
    # Reverse the list to make indexing easier
    digits_reversed = digits[::-1]

    for i, digit in enumerate(digits_reversed):
        if i % 2 == 1:  # Every second digit from the right (indices 1, 3, 5, ...)
            doubled = digit * 2
            if doubled > 9:
                doubled -= 9
            checksum += doubled
        else:  # Non-doubled digits (indices 0, 2, 4, ...)
            checksum += digit

    # Valid if checksum is divisible by 10
    return checksum % 10 == 0


if __name__ == "__main__":
    # Quick validation examples
    test_cases = [
        ("4111111111111111", True),   # Valid Visa test card
        ("5500000000000004", True),   # Valid MasterCard test card
        ("378282246310005", True),    # Valid Amex test card
        ("4111111111111112", False),  # Invalid checksum
        ("1234567890123456", False),  # Random number
        ("4111 1111 1111 1111", True), # Valid with spaces
    ]

    print("Luhn Validator - Quick Test")
    print("-" * 40)
    for card, expected in test_cases:
        result = validate_luhn(card)
        status = "✓" if result == expected else "✗"
        print(f"{status} Card: {card} -> {result} (expected: {expected})")
