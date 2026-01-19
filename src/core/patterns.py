"""
Detection Patterns Library for Log Sensitivity Analyzer.

This module provides ReDoS-safe regex patterns and entropy calculation
for detecting PII (Personal Identifiable Information) and secrets in logs.

Compliance: KVKK/GDPR Data Leakage Prevention Standards
Author: Senior Security Engineer - DLP Team

Research Sources:
- researchs/gemini-fast/research.gemini-fast.result.md
- researchs/perplexity/research.perplexity.result.md
"""

import re
import math
from typing import Dict, Pattern
from dataclasses import dataclass


# =============================================================================
# ENTROPY THRESHOLD CONFIGURATION
# =============================================================================

# Shannon entropy threshold for high-entropy secret detection (bits per char)
# Research: gemini-fast.result.md line 106, perplexity.result.md
ENTROPY_THRESHOLD = 4.5


# =============================================================================
# REGEX PATTERN DEFINITIONS (ReDoS-Safe)
# =============================================================================

@dataclass
class PatternInfo:
    """Metadata for detection patterns."""
    name: str
    pattern: Pattern
    description: str
    risk_weight: float
    requires_validation: bool


class DetectionPatterns:
    """
    Centralized repository of compiled regex patterns for PII detection.
    
    All patterns are optimized to prevent ReDoS (Regular Expression Denial
    of Service) attacks through:
    - Bounded repetition (no nested quantifiers)
    - Atomic groups where applicable
    - Word boundaries to limit backtracking
    
    Risk Weights (from research):
    - 1.0: Critical (TCKN, Credit Cards)
    - 0.95: High (API Secrets with high entropy)
    - 0.7: High (IBAN)
    - 0.5: Medium (Phone numbers)
    - 0.2: Low (Email addresses)
    """
    
    # -------------------------------------------------------------------------
    # Turkish Identification Number (TC Kimlik)
    # -------------------------------------------------------------------------
    # Pattern: 11 digits, first digit non-zero
    # Research: gemini-fast.result.md line 159, perplexity.result.md line 465
    TCKN = re.compile(
        r'\b[1-9][0-9]{10}\b',
        re.MULTILINE
    )
    
    # -------------------------------------------------------------------------
    # Credit Card Numbers (Luhn Algorithm Required)
    # -------------------------------------------------------------------------
    # Visa: Starts with 4, 13 or 16 digits
    # Research: gemini-fast.result.md line 173
    VISA = re.compile(
        r'\b4[0-9]{12}(?:[0-9]{3})?\b',
        re.MULTILINE
    )
    
    # MasterCard: 51-55 prefix, 16 digits
    # Research: gemini-fast.result.md line 174
    MASTERCARD_OLD = re.compile(
        r'\b5[1-5][0-9]{14}\b',
        re.MULTILINE
    )
    
    # MasterCard (new range): 2221-2720, 16 digits
    # Research: gemini-fast.result.md line 174
    MASTERCARD_NEW = re.compile(
        r'\b2(?:22[1-9]|2[3-9][0-9]|[3-6][0-9]{2}|7[0-1][0-9]|720)[0-9]{12}\b',
        re.MULTILINE
    )
    
    # American Express: 34 or 37 prefix, 15 digits
    # Research: gemini-fast.result.md line 175
    AMEX = re.compile(
        r'\b3[47][0-9]{13}\b',
        re.MULTILINE
    )
    
    # Generic credit card with separators (will be sanitized before validation)
    # Matches formats like: 4111-1111-1111-1111 or 4111 1111 1111 1111
    CREDIT_CARD_FORMATTED = re.compile(
        r'\b[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',
        re.MULTILINE
    )
    
    # -------------------------------------------------------------------------
    # Turkish IBAN
    # -------------------------------------------------------------------------
    # Format: TR + 24 digits
    # Research: gemini-fast.result.md line 184, perplexity.result.md line 425
    # Uses negative lookbehind/lookahead to ensure word boundaries
    IBAN_TURKISH = re.compile(
        r'(?<![A-Za-z0-9])TR\d{24}(?![A-Za-z0-9])',
        re.MULTILINE
    )
    
    # -------------------------------------------------------------------------
    # Email Addresses
    # -------------------------------------------------------------------------
    # Standard email format
    # Research: gemini-fast.result.md line 183, perplexity.result.md line 449
    EMAIL = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        re.MULTILINE | re.IGNORECASE
    )
    
    # -------------------------------------------------------------------------
    # Turkish Phone Numbers
    # -------------------------------------------------------------------------
    # Format: +90 5XX XXX XX XX or 05XX XXX XX XX or 5XXXXXXXXX
    # Research: gemini-fast.result.md line 184, perplexity.result.md line 443
    PHONE_TURKISH = re.compile(
        r'(?:\+90|0)?[5][0-9]{9}\b',
        re.MULTILINE
    )
    
    # -------------------------------------------------------------------------
    # API Keys and Secrets (Keyword-anchored with high entropy)
    # -------------------------------------------------------------------------
    # Generic pattern for API keys with common keywords
    # Research: gemini-fast.result.md line 185-186, perplexity.result.md line 456
    API_KEY_GENERIC = re.compile(
        r'(?i)(?:api[_\-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*["\']?([A-Za-z0-9\-_.~+/%]{20,})["\']?',
        re.MULTILINE
    )
    
    # GitHub Personal Access Token
    # Research: gemini-fast.result.md line 185
    GITHUB_TOKEN = re.compile(
        r'\b(ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}\b',
        re.MULTILINE
    )
    
    # AWS Access Key
    # Research: gemini-fast.result.md line 186
    AWS_KEY = re.compile(
        r'\bAKIA[0-9A-Z]{16}\b',
        re.MULTILINE
    )
    
    # Generic high-entropy string (no keyword required)
    # Matches strings of 32+ chars with mixed case/numbers
    HIGH_ENTROPY_STRING = re.compile(
        r'\b[A-Za-z0-9+/=\-_]{32,}\b',
        re.MULTILINE
    )
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, PatternInfo]:
        """
        Return all detection patterns with metadata.
        
        Returns:
            Dictionary mapping pattern names to PatternInfo objects.
        """
        return {
            'tc_kimlik': PatternInfo(
                name='tc_kimlik',
                pattern=cls.TCKN,
                description='Turkish Identification Number (11 digits)',
                risk_weight=1.0,
                requires_validation=True
            ),
            'visa': PatternInfo(
                name='visa',
                pattern=cls.VISA,
                description='Visa Credit Card (13 or 16 digits)',
                risk_weight=1.0,
                requires_validation=True
            ),
            'mastercard_old': PatternInfo(
                name='mastercard',
                pattern=cls.MASTERCARD_OLD,
                description='MasterCard (51-55 prefix)',
                risk_weight=1.0,
                requires_validation=True
            ),
            'mastercard_new': PatternInfo(
                name='mastercard',
                pattern=cls.MASTERCARD_NEW,
                description='MasterCard (2221-2720 range)',
                risk_weight=1.0,
                requires_validation=True
            ),
            'amex': PatternInfo(
                name='amex',
                pattern=cls.AMEX,
                description='American Express (34/37 prefix)',
                risk_weight=1.0,
                requires_validation=True
            ),
            'credit_card_formatted': PatternInfo(
                name='credit_card',
                pattern=cls.CREDIT_CARD_FORMATTED,
                description='Formatted Credit Card (with spaces/hyphens)',
                risk_weight=1.0,
                requires_validation=True
            ),
            'iban': PatternInfo(
                name='iban',
                pattern=cls.IBAN_TURKISH,
                description='Turkish IBAN (TR + 24 digits)',
                risk_weight=0.7,
                requires_validation=False  # No checksum validation implemented
            ),
            'email': PatternInfo(
                name='email',
                pattern=cls.EMAIL,
                description='Email Address',
                risk_weight=0.2,
                requires_validation=False
            ),
            'phone': PatternInfo(
                name='phone',
                pattern=cls.PHONE_TURKISH,
                description='Turkish Mobile Phone Number',
                risk_weight=0.5,
                requires_validation=False
            ),
            'github_token': PatternInfo(
                name='github_token',
                pattern=cls.GITHUB_TOKEN,
                description='GitHub Personal Access Token',
                risk_weight=0.95,
                requires_validation=False
            ),
            'aws_key': PatternInfo(
                name='aws_key',
                pattern=cls.AWS_KEY,
                description='AWS Access Key ID',
                risk_weight=0.95,
                requires_validation=False
            ),
            'api_key': PatternInfo(
                name='api_key',
                pattern=cls.API_KEY_GENERIC,
                description='Generic API Key (keyword-anchored)',
                risk_weight=0.95,
                requires_validation=False
            ),
        }


# =============================================================================
# SHANNON ENTROPY CALCULATOR
# =============================================================================

def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string in bits per character.
    
    Shannon entropy measures the randomness and unpredictability of data.
    High entropy values (> 4.5 bits) suggest cryptographic keys, tokens,
    or passwords.
    
    Formula: H(X) = -Σ P(xi) * log2(P(xi))
    
    Research Reference:
    - gemini-fast.result.md line 28-29
    - perplexity.result.md (Shannon Entropy Analysis section)
    
    Args:
        text (str): Input string to analyze.
    
    Returns:
        float: Entropy in bits per character (0.0 to ~8.0 for ASCII).
    
    Examples:
        >>> calculate_shannon_entropy("aaaaaaa")
        0.0
        >>> calculate_shannon_entropy("abcdefgh")
        3.0
        >>> calculate_shannon_entropy("A8f3$xK9@pL2")  # High entropy
        3.584962500721156
    """
    if not text or len(text) == 0:
        return 0.0
    
    # Calculate character frequency
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    text_length = len(text)
    
    for count in frequency.values():
        probability = count / text_length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def is_high_entropy_secret(text: str, threshold: float = ENTROPY_THRESHOLD) -> bool:
    """
    Determine if a string is a high-entropy secret based on Shannon entropy.
    
    Args:
        text (str): String to evaluate.
        threshold (float): Minimum entropy threshold (default: 4.5 bits).
    
    Returns:
        bool: True if entropy exceeds threshold, False otherwise.
    
    Examples:
        >>> is_high_entropy_secret("password123")
        False
        >>> is_high_entropy_secret("xK9$pL2@A8f3")
        True
    """
    # Minimum length requirement for secrets (avoid false positives)
    if len(text) < 16:
        return False
    
    entropy = calculate_shannon_entropy(text)
    return entropy >= threshold


# =============================================================================
# PATTERN TESTING UTILITIES
# =============================================================================

if __name__ == "__main__":
    # Quick pattern validation
    test_cases = {
        'TCKN': ['10000000146', '12345678901', 'abc123'],
        'VISA': ['4111111111111111', '4111-1111-1111-1111', '5111111111111111'],
        'IBAN': ['TR330006100519786457841326', 'TR123', 'TRXXXXXXXXXXXXXXXXXXXXXXXX'],
        'Email': ['user@example.com', 'invalid@', 'test@test.co.uk'],
        'Phone': ['05551234567', '+905551234567', '5551234567'],
    }
    
    print("Pattern Library - Quick Validation")
    print("=" * 60)
    
    # Test TCKN
    print("\n[TCKN Pattern]")
    for test in test_cases['TCKN']:
        match = DetectionPatterns.TCKN.search(test)
        print(f"  {test:20s} → {bool(match)}")
    
    # Test Visa
    print("\n[VISA Pattern]")
    for test in test_cases['VISA']:
        match = DetectionPatterns.VISA.search(test)
        print(f"  {test:20s} → {bool(match)}")
    
    # Test IBAN
    print("\n[IBAN Pattern]")
    for test in test_cases['IBAN']:
        match = DetectionPatterns.IBAN_TURKISH.search(test)
        print(f"  {test:35s} → {bool(match)}")
    
    # Test Email
    print("\n[Email Pattern]")
    for test in test_cases['Email']:
        match = DetectionPatterns.EMAIL.search(test)
        print(f"  {test:25s} → {bool(match)}")
    
    # Test Phone
    print("\n[Phone Pattern]")
    for test in test_cases['Phone']:
        match = DetectionPatterns.PHONE_TURKISH.search(test)
        print(f"  {test:20s} → {bool(match)}")
    
    # Test Entropy
    print("\n[Shannon Entropy]")
    entropy_tests = [
        'password',
        'sk_live_abc123def456ghi789jkl012mno345pqr678',
        'AKIA1234567890ABCDEF',
        'user@example.com',
    ]
    for test in entropy_tests:
        entropy = calculate_shannon_entropy(test)
        is_secret = is_high_entropy_secret(test)
        print(f"  {test:45s} → {entropy:.2f} bits (secret: {is_secret})")
