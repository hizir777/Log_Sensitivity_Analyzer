"""
Turkish Identification Number (TCKN) Validator Module.

This module provides mathematical validation for Turkish Identification Numbers
using the Modulo 11 checksum algorithm as mandated by Turkish regulations.

Author: Senior Python Security Developer
Compliance: KVKK/GDPR Data Leakage Prevention Standards
"""


def _sanitize_tckn(tckn: str) -> str:
    """
    Sanitize TCKN input by removing common separators.

    Args:
        tckn (str): Raw TCKN input string.

    Returns:
        str: Sanitized numeric string with spaces and hyphens removed.

    Examples:
        >>> _sanitize_tckn("123 456 789 01")
        '12345678901'
        >>> _sanitize_tckn("123-456-789-01")
        '12345678901'
    """
    return tckn.replace(" ", "").replace("-", "")


def validate_tckn(tckn: str) -> bool:
    """
    Validate Turkish Identification Number using Modulo 11 algorithm.

    The TCKN is an 11-digit number where:
    - First digit must be non-zero (1-9)
    - 10th digit is calculated via: ((sum_odd * 7) - sum_even) % 10
      where sum_odd = sum of digits at positions 1,3,5,7,9
      and sum_even = sum of digits at positions 2,4,6,8
    - 11th digit is calculated via: sum(first 10 digits) % 10

    Args:
        tckn (str): Turkish Identification Number as string.

    Returns:
        bool: True if TCKN is mathematically valid, False otherwise.

    Raises:
        None: Function returns False for all invalid inputs.

    Examples:
        >>> validate_tckn("12345678901")  # Example invalid TCKN
        False
        >>> validate_tckn("10000000146")  # Valid test TCKN
        True

    Algorithm Reference:
        Turkish Ministry of Interior - MERNIS System Specification
        https://gist.github.com/onury/7a380f906b1eb46dc2f0bb089caf7d12
    """
    # Sanitize input
    tckn = _sanitize_tckn(tckn)

    # Basic validation: must be exactly 11 digits
    if len(tckn) != 11:
        return False

    # Check if all characters are digits
    if not tckn.isdigit():
        return False

    # Convert to list of integers
    digits = [int(d) for d in tckn]

    # First digit must be non-zero
    if digits[0] == 0:
        return False

    # Calculate sum of odd-indexed digits (positions 1,3,5,7,9 -> indices 0,2,4,6,8)
    sum_odd = sum(digits[0:9:2])  # indices 0,2,4,6,8

    # Calculate sum of even-indexed digits (positions 2,4,6,8 -> indices 1,3,5,7)
    sum_even = sum(digits[1:8:2])  # indices 1,3,5,7

    # Rule 1: Validate 10th digit
    # (sum_odd * 7 - sum_even) % 10 must equal 10th digit (index 9)
    tenth_digit_check = ((sum_odd * 7) - sum_even) % 10
    if tenth_digit_check != digits[9]:
        return False

    # Rule 2: Validate 11th digit
    # Sum of first 10 digits % 10 must equal 11th digit (index 10)
    eleventh_digit_check = sum(digits[0:10]) % 10
    if eleventh_digit_check != digits[10]:
        return False

    return True


if __name__ == "__main__":
    # Quick validation examples
    test_cases = [
        ("10000000146", True),   # Valid TCKN
        ("12345678901", False),  # Invalid checksum
        ("00000000000", False),  # First digit zero
        ("1234567890", False),   # Too short
    ]

    print("TCKN Validator - Quick Test")
    print("-" * 40)
    for tckn, expected in test_cases:
        result = validate_tckn(tckn)
        status = "✓" if result == expected else "✗"
        print(f"{status} TCKN: {tckn} -> {result} (expected: {expected})")
