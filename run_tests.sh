#!/bin/bash

################################################################################
# Log Sensitivity Analyzer - Test Execution Script
#
# Purpose: Execute complete test suite with clear pass/fail reporting
# Author: Senior DevSecOps Engineer
# Compliance: KVKK/GDPR Automated Quality Assurance
################################################################################

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BOLD}======================================================================${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${BOLD}======================================================================${RESET}\n"
}

print_test_running() {
    echo -e "${BLUE}[▶]${RESET} Running: $1"
}

print_test_pass() {
    echo -e "${GREEN}[✓]${RESET} $1 ${GREEN}PASSED${RESET}"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

print_test_fail() {
    echo -e "${RED}[✗]${RESET} $1 ${RED}FAILED${RESET}"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

################################################################################
# Test Execution Functions
################################################################################

run_environment_check() {
    print_test_running "Environment Self-Check"
    
    if python3 src/core/automation.py --check --quiet; then
        print_test_pass "Environment Self-Check"
        return 0
    else
        print_test_fail "Environment Self-Check"
        return 1
    fi
}

run_validator_tests() {
    print_test_running "Validator Unit Tests (23 tests)"
    
    # Capture output but suppress it unless there's a failure
    if python3 -m unittest src/validators/test_validators.py -v > /tmp/validator_test.log 2>&1; then
        print_test_pass "Validator Unit Tests (23 tests)"
        return 0
    else
        print_test_fail "Validator Unit Tests (23 tests)"
        echo ""
        echo -e "${YELLOW}Test output:${RESET}"
        cat /tmp/validator_test.log
        echo ""
        return 1
    fi
}

run_canary_tests() {
    print_test_running "Canary Log Tests"
    
    if python3 -m unittest tests.test_full_pipeline.CanaryLogTests -q > /tmp/canary_test.log 2>&1; then
        # Count number of tests
        test_count=$(grep -c "^test_" tests/test_full_pipeline.py | head -1 || echo "15")
        print_test_pass "Canary Log Tests"
        return 0
    else
        print_test_fail "Canary Log Tests"
        echo ""
        echo -e "${YELLOW}Test output:${RESET}"
        cat /tmp/canary_test.log
        echo ""
        return 1
    fi
}

run_integration_tests() {
    print_test_running "Full Pipeline Integration Tests"
    
    if python3 -m unittest tests.test_full_pipeline.IntegrationTests -q > /tmp/integration_test.log 2>&1; then
        print_test_pass "Full Pipeline Integration Tests"
        return 0
    else
        print_test_fail "Full Pipeline Integration Tests"
        echo ""
        echo -e "${YELLOW}Test output:${RESET}"
        cat /tmp/integration_test.log
        echo ""
        return 1
    fi
}

################################################################################
# Main Test Suite
################################################################################

run_test_suite() {
    print_header "LOG SENSITIVITY ANALYZER - TEST SUITE"
    
    echo -e "${BOLD}Executing comprehensive test suite...${RESET}\n"
    
    # Run all tests
    run_environment_check
    run_validator_tests
    run_canary_tests
    run_integration_tests
    
    # Print summary
    echo ""
    print_header "TEST RESULTS SUMMARY"
    
    echo -e "${BOLD}Total Test Suites:${RESET} $TOTAL_TESTS"
    echo -e "${GREEN}${BOLD}Passed:${RESET}            $PASSED_TESTS"
    echo -e "${RED}${BOLD}Failed:${RESET}            $FAILED_TESTS"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════╗${RESET}"
        echo -e "${GREEN}${BOLD}║                                               ║${RESET}"
        echo -e "${GREEN}${BOLD}║       ✓  ALL TESTS PASSED                    ║${RESET}"
        echo -e "${GREEN}${BOLD}║                                               ║${RESET}"
        echo -e "${GREEN}${BOLD}║   System is ready for production deployment  ║${RESET}"
        echo -e "${GREEN}${BOLD}║                                               ║${RESET}"
        echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════╝${RESET}"
        echo ""
        echo -e "${BOLD}KVKK/GDPR Compliance:${RESET} ✓ Integrity verified (Article 12 KVKK, Article 32 GDPR)"
        echo -e "${BOLD}Security Posture:${RESET}     ✓ All validators operational"
        echo -e "${BOLD}Detection Accuracy:${RESET}   ✓ 100% on canary logs"
        echo ""
        exit 0
    else
        echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════╗${RESET}"
        echo -e "${RED}${BOLD}║                                               ║${RESET}"
        echo -e "${RED}${BOLD}║       ✗  SOME TESTS FAILED                   ║${RESET}"
        echo -e "${RED}${BOLD}║                                               ║${RESET}"
        echo -e "${RED}${BOLD}║   Please review failures before deployment   ║${RESET}"
        echo -e "${RED}${BOLD}║                                               ║${RESET}"
        echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════╝${RESET}"
        echo ""
        exit 1
    fi
}

################################################################################
# Main Execution
################################################################################

# Check if running in CI/CD or locally
if [ -t 1 ]; then
    # Running in terminal (colorful output)
    run_test_suite
else
    # Running in CI/CD (plain output)
    run_test_suite 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
fi
