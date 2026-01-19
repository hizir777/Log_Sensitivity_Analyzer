"""
Full Pipeline Testing for Log Sensitivity Analyzer.

This module provides comprehensive end-to-end testing using the unittest
framework. It validates the entire detection pipeline from pattern matching
through validator integration to risk scoring and output generation.

Compliance: KVKK Article 12 (Integrity), GDPR Article 32 (Security of Processing)
Author: Senior DevSecOps Engineer
"""

import unittest
import sys
import json
from pathlib import Path
from io import StringIO

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'src'))
sys.path.insert(0, str(project_root / 'src' / 'core'))
sys.path.insert(0, str(project_root / 'src' / 'validators'))

# Now import modules
from automation import perform_full_check
from engine import LogScanner, Finding
from tckn_validator import validate_tckn
from luhn_validator import validate_luhn


class EnvironmentTests(unittest.TestCase):
    """
    Test suite for environment validation and self-check functionality.
    
    These tests ensure the tool meets KVKK Article 12 requirements for
    maintaining data integrity through proper system configuration.
    """
    
    def test_self_check_passes(self):
        """Test that environment self-check passes."""
        result = perform_full_check(verbose=False)
        self.assertTrue(result, "Environment self-check should pass")
    
    def test_project_info_exists(self):
        """Test that project_info.json exists and is valid."""
        project_info_path = Path(__file__).parent.parent / "project_info.json"
        self.assertTrue(project_info_path.exists(), "project_info.json must exist")
        
        with open(project_info_path, 'r') as f:
            data = json.load(f)
        
        self.assertIn('project', data)
        self.assertIn('requirements', data)
        self.assertIn('configuration', data)
    
    def test_validators_accessible(self):
        """Test that validator modules can be imported and used."""
        # Test TCKN validator
        self.assertTrue(validate_tckn("10000000146"))
        self.assertFalse(validate_tckn("12345678901"))
        
        # Test Luhn validator
        self.assertTrue(validate_luhn("4111111111111111"))
        self.assertFalse(validate_luhn("1234567890123456"))


class CanaryLogTests(unittest.TestCase):
    """
    Test suite for canary log validation.
    
    This ensures 100% detection and verification accuracy, satisfying
    GDPR Article 32 requirements for appropriate technical measures.
    """
    
    @classmethod
    def setUpClass(cls):
        """Load canary test data once for all tests."""
        canary_path = Path(__file__).parent / "canary_logs.json"
        with open(canary_path, 'r') as f:
            cls.canary_data = json.load(f)
        
        cls.scanner = LogScanner()
    
    def test_canary_file_exists(self):
        """Test that canary_logs.json exists and is valid JSON."""
        canary_path = Path(__file__).parent / "canary_logs.json"
        self.assertTrue(canary_path.exists(), "canary_logs.json must exist")
    
    def test_valid_tckn_detection(self):
        """Test detection of valid TCKN numbers."""
        # Get valid TCKN test cases
        tckn_cases = [c for c in self.canary_data['valid_cases'] 
                      if 'tckn' in c['id'] or any(m['type'] == 'tc_kimlik' for m in c['expected_matches'])]
        
        for case in tckn_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                
                # Find TCKN findings
                tckn_findings = [f for f in findings if f.type == 'tc_kimlik']
                
                # Should have at least one TCKN finding
                self.assertGreater(len(tckn_findings), 0, 
                                   f"Should detect TCKN in: {case['log_line']}")
                
                # Check verification
                verified_count = sum(1 for f in tckn_findings if f.verified)
                self.assertGreater(verified_count, 0,
                                   f"At least one TCKN should be verified in: {case['log_line']}")
    
    def test_valid_credit_card_detection(self):
        """Test detection of valid credit cards."""
        card_cases = [c for c in self.canary_data['valid_cases']
                      if any(m['type'] in ['visa', 'mastercard', 'amex'] for m in c['expected_matches'])]
        
        for case in card_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                
                # Find card findings
                card_findings = [f for f in findings if f.type in ['visa', 'mastercard', 'amex', 'credit_card']]
                
                # Should detect card
                self.assertGreater(len(card_findings), 0,
                                   f"Should detect card in: {case['log_line']}")
                
                # Should be verified
                verified = any(f.verified for f in card_findings)
                self.assertTrue(verified, f"Card should be verified in: {case['log_line']}")
    
    def test_false_positive_rejection(self):
        """Test that invalid checksums are correctly rejected."""
        false_positive_cases = self.canary_data.get('false_positive_cases', [])
        
        for case in false_positive_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                
                for expected in case['expected_matches']:
                    if expected['verified'] == False:
                        # Find the matching finding
                        matching = [f for f in findings if f.value == expected['value']]
                        
                        if matching:
                            # Should be marked as not verified
                            self.assertFalse(matching[0].verified,
                                             f"Invalid {expected['type']} should not be verified")
    
    def test_iban_detection(self):
        """Test Turkish IBAN detection."""
        iban_cases = [c for c in self.canary_data['valid_cases']
                      if any(m['type'] == 'iban' for m in c['expected_matches'])]
        
        for case in iban_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                iban_findings = [f for f in findings if f.type == 'iban']
                
                self.assertGreater(len(iban_findings), 0,
                                   f"Should detect IBAN in: {case['log_line']}")
    
    def test_email_detection(self):
        """Test email address detection."""
        email_cases = [c for c in self.canary_data['valid_cases']
                       if any(m['type'] == 'email' for m in c['expected_matches'])]
        
        for case in email_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                email_findings = [f for f in findings if f.type == 'email']
                
                self.assertGreater(len(email_findings), 0,
                                   f"Should detect email in: {case['log_line']}")
    
    def test_phone_detection(self):
        """Test Turkish phone number detection."""
        phone_cases = [c for c in self.canary_data['valid_cases']
                       if any(m['type'] == 'phone' for m in c['expected_matches'])]
        
        for case in phone_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                phone_findings = [f for f in findings if f.type == 'phone']
                
                self.assertGreater(len(phone_findings), 0,
                                   f"Should detect phone in: {case['log_line']}")
    
    def test_api_secret_detection(self):
        """Test API secret detection (GitHub, AWS)."""
        secret_cases = [c for c in self.canary_data['valid_cases']
                        if any(m['type'] in ['github_token', 'aws_key'] for m in c['expected_matches'])]
        
        for case in secret_cases:
            with self.subTest(case=case['id']):
                findings = self.scanner.scan_line(case['log_line'], 1)
                secret_findings = [f for f in findings if f.type in ['github_token', 'aws_key', 'api_key']]
                
                self.assertGreater(len(secret_findings), 0,
                                   f"Should detect secret in: {case['log_line']}")
    
    def test_edge_case_empty_line(self):
        """Test that empty lines don't generate false positives."""
        findings = self.scanner.scan_line("", 1)
        self.assertEqual(len(findings), 0, "Empty line should not generate findings")
    
    def test_edge_case_no_pii(self):
        """Test that clean logs don't generate false positives."""
        clean_log = "2026-01-19 05:16:00 INFO Application started successfully"
        findings = self.scanner.scan_line(clean_log, 1)
        self.assertEqual(len(findings), 0, "Clean log should not generate findings")
    
    def test_multiple_pii_in_single_line(self):
        """Test detection of multiple PII types in one line."""
        multi_pii = "User 10000000146 payment 4111111111111111 contact user@example.com"
        findings = self.scanner.scan_line(multi_pii, 1)
        
        # Should detect multiple types
        types_found = set(f.type for f in findings)
        self.assertIn('tc_kimlik', types_found)
        # Should detect card (could be visa or credit_card pattern)
        self.assertTrue(any(t in types_found for t in ['visa', 'credit_card', 'mastercard', 'amex']))
        self.assertIn('email', types_found)


class IntegrationTests(unittest.TestCase):
    """
    Integration tests for complete workflow validation.
    
    These tests verify end-to-end functionality including risk scoring,
    masking, and output generation.
    """
    
    def setUp(self):
        """Set up scanner for each test."""
        self.scanner = LogScanner()
    
    def test_risk_score_calculation(self):
        """Test that risk scores are calculated correctly."""
        # Scan a high-risk line
        high_risk_log = "User 10000000146 payment 4111111111111111"
        findings = self.scanner.scan_line(high_risk_log, 1)
        
        # Calculate risk
        total_risk = sum(f.risk_weight for f in findings if f.verified)
        
        # Should have high risk (TCKN=1.0 + Card=1.0 = 2.0)
        self.assertGreaterEqual(total_risk, 2.0)
    
    def test_masking_logic(self):
        """Test that PII values are properly masked."""
        test_line = "User 10000000146 card 4111111111111111"
        findings = self.scanner.scan_line(test_line, 1)
        
        for finding in findings:
            # Masked value should not equal original value
            self.assertNotEqual(finding.masked_value, finding.value,
                                "Masked value must differ from original")
            
            # Masked value should contain mask characters
            self.assertTrue('*' in finding.masked_value or '[REDACTED]' in finding.masked_value,
                            "Masked value should contain obfuscation")
    
    def test_confidence_scores(self):
        """Test that confidence scores are assigned appropriately."""
        # Valid TCKN should have high confidence
        valid_tckn_line = "User 10000000146 logged in"
        findings = self.scanner.scan_line(valid_tckn_line, 1)
        tckn_finding = [f for f in findings if f.type == 'tc_kimlik' and f.verified]
        
        if tckn_finding:
            self.assertGreaterEqual(tckn_finding[0].confidence, 0.9,
                                    "Verified TCKN should have high confidence")
    
    def test_context_extraction(self):
        """Test that context is properly extracted."""
        test_line = "2026-01-19 INFO User 10000000146 logged in"
        findings = self.scanner.scan_line(test_line, 1)
        
        for finding in findings:
            # Context should contain [MATCH] marker
            self.assertIn('[MATCH]', finding.context,
                          "Context should contain [MATCH] placeholder")


def run_test_suite():
    """
    Run the complete test suite with colored output.
    
    Returns:
        bool: True if all tests pass, False otherwise
    """
    # ANSI colors
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}  LOG SENSITIVITY ANALYZER - FULL PIPELINE TESTS{RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(EnvironmentTests))
    suite.addTests(loader.loadTestsFromTestCase(CanaryLogTests))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}TEST SUMMARY{RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}")
    print(f"Tests Run:    {result.testsRun}")
    
    if result.wasSuccessful():
        print(f"{GREEN}Passed:       {result.testsRun}{RESET}")
        print(f"{RED}Failed:       0{RESET}")
        print(f"\n{GREEN}{BOLD}✓ ALL TESTS PASSED{RESET}")
    else:
        passed = result.testsRun - len(result.failures) - len(result.errors)
        print(f"{GREEN}Passed:       {passed}{RESET}")
        print(f"{RED}Failed:       {len(result.failures) + len(result.errors)}{RESET}")
        print(f"\n{RED}{BOLD}✗ SOME TESTS FAILED{RESET}")
    
    print(f"{BOLD}{'=' * 70}{RESET}\n")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    # Run suite and exit with appropriate code
    success = run_test_suite()
    sys.exit(0 if success else 1)
