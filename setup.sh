#!/bin/bash

################################################################################
# Log Sensitivity Analyzer - Environment Setup Script
# 
# Purpose: Automated environment validation and setup
# Author: Senior DevSecOps Engineer
# Compliance: KVKK/GDPR
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

################################################################################
# Helper Functions
################################################################################

print_header() {
    echo -e "\n${BOLD}======================================================================${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${BOLD}======================================================================${RESET}\n"
}

print_step() {
    echo -e "${BLUE}[STEP]${RESET} $1"
}

print_success() {
    echo -e "${GREEN}✓${RESET} $1"
}

print_error() {
    echo -e "${RED}✗${RESET} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${RESET} $1"
}

################################################################################
# Setup Steps
################################################################################

setup_environment() {
    print_header "LOG SENSITIVITY ANALYZER - ENVIRONMENT SETUP"
    
    # Step 1: Check Python version
    print_step "Checking Python version..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python ${PYTHON_VERSION} found"
    else
        print_error "Python 3 not found. Please install Python 3.10 or higher."
        exit 1
    fi
    
    # Step 2: Verify directory structure
    print_step "Verifying directory structure..."
    
    required_dirs=("src" "src/core" "src/validators" "tests")
    for dir in "${required_dirs[@]}"; do
        if [ -d "$dir" ]; then
            print_success "Directory exists: $dir"
        else
            print_warning "Creating directory: $dir"
            mkdir -p "$dir"
        fi
    done
    
    # Step 3: Check project files
    print_step "Checking critical project files..."
    
    required_files=(
        "project_info.json"
        "src/core/engine.py"
        "src/core/patterns.py"
        "src/core/automation.py"
        "src/validators/tckn_validator.py"
        "src/validators/luhn_validator.py"
    )
    
    missing_files=()
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            print_success "File exists: $file"
        else
            print_error "Missing file: $file"
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        echo -e "\n${RED}${BOLD}Setup cannot continue. Missing critical files.${RESET}"
        exit 1
    fi
    
    # Step 4: Run environment self-check
    print_step "Running environment self-check..."
    
    if python3 src/core/automation.py --check; then
        print_success "Environment self-check passed"
    else
        print_error "Environment self-check failed"
        exit 1
    fi
    
    # Step 5: Create test directories
    print_step "Setting up test directories..."
    
    if [ ! -d "test_logs" ]; then
        mkdir -p test_logs
        print_success "Created test_logs directory"
    fi
    
    # Step 6: Verify test files
    print_step "Checking test files..."
    
    if [ -f "tests/canary_logs.json" ]; then
        print_success "Canary test data found"
    else
        print_warning "Canary test data not found (tests may fail)"
    fi
    
    if [ -f "tests/test_full_pipeline.py" ]; then
        print_success "Test suite found"
    else
        print_warning "Test suite not found"
    fi
    
    # Final summary
    echo ""
    print_header "SETUP COMPLETE"
    print_success "Environment is ready for use"
    echo -e "\n${BOLD}Next steps:${RESET}"
    echo "  1. Run tests: ./run_tests.sh"
    echo "  2. Scan a log: python src/core/engine.py --scan <logfile>"
    echo ""
    
    exit 0
}

################################################################################
# Main Execution
################################################################################

setup_environment
