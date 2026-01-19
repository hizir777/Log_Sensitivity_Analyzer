"""
Automation and Self-Check Module for Log Sensitivity Analyzer.

This module provides standalone environment validation capabilities to ensure
the system is properly configured before execution. It can be run independently
for CI/CD integration and pre-deployment checks.

Compliance: KVKK/GDPR Integrity and Accountability Principles
Author: Senior DevSecOps Engineer
"""

import sys
import json
import os
from pathlib import Path
from typing import List, Tuple


# =============================================================================
# ENVIRONMENT VALIDATION
# =============================================================================

def check_python_version() -> Tuple[bool, str]:
    """
    Verify Python version is 3.10 or higher.
    
    Returns:
        Tuple of (success, message)
    """
    required = (3, 10)
    current = sys.version_info[:2]
    
    if current >= required:
        return (True, f"✓ Python {current[0]}.{current[1]} (required: {required[0]}.{required[1]}+)")
    else:
        return (False, f"✗ Python {current[0]}.{current[1]} - REQUIRED: {required[0]}.{required[1]}+")


def check_project_info() -> Tuple[bool, str]:
    """
    Verify project_info.json exists and has valid structure.
    
    Returns:
        Tuple of (success, message)
    """
    project_root = Path(__file__).parent.parent.parent
    project_info_path = project_root / "project_info.json"
    
    if not project_info_path.exists():
        return (False, f"✗ project_info.json not found at {project_info_path}")
    
    try:
        with open(project_info_path, 'r') as f:
            data = json.load(f)
            
        # Validate required sections
        required_sections = ['project', 'requirements', 'configuration']
        missing = [s for s in required_sections if s not in data]
        
        if missing:
            return (False, f"✗ project_info.json missing sections: {', '.join(missing)}")
        
        return (True, f"✓ project_info.json valid with all required sections")
    
    except json.JSONDecodeError as e:
        return (False, f"✗ Invalid JSON in project_info.json: {e}")
    except Exception as e:
        return (False, f"✗ Error reading project_info.json: {e}")


def check_required_modules() -> Tuple[bool, str]:
    """
    Verify all required Python modules are available.
    
    Returns:
        Tuple of (success, message)
    """
    required_modules = [
        're', 'json', 'sys', 'os', 'pathlib', 'dataclasses',
        'datetime', 'argparse', 'math', 'typing'
    ]
    
    missing = []
    for module_name in required_modules:
        try:
            __import__(module_name)
        except ImportError:
            missing.append(module_name)
    
    if missing:
        return (False, f"✗ Missing modules: {', '.join(missing)}")
    
    return (True, f"✓ All {len(required_modules)} required modules available")


def check_validators() -> Tuple[bool, str]:
    """
    Verify validator modules are accessible.
    
    Returns:
        Tuple of (success, message)
    """
    validator_path = Path(__file__).parent.parent / 'validators'
    
    if not validator_path.exists():
        return (False, f"✗ Validators directory not found: {validator_path}")
    
    required_files = ['tckn_validator.py', 'luhn_validator.py']
    missing = []
    
    for filename in required_files:
        if not (validator_path / filename).exists():
            missing.append(filename)
    
    if missing:
        return (False, f"✗ Missing validators: {', '.join(missing)}")
    
    return (True, f"✓ All {len(required_files)} validators found")


def check_patterns_module() -> Tuple[bool, str]:
    """
    Verify patterns module exists.
    
    Returns:
        Tuple of (success, message)
    """
    patterns_path = Path(__file__).parent / 'patterns.py'
    
    if not patterns_path.exists():
        return (False, f"✗ patterns.py not found at {patterns_path}")
    
    return (True, f"✓ patterns.py module found")


def check_engine_module() -> Tuple[bool, str]:
    """
    Verify engine module exists.
    
    Returns:
        Tuple of (success, message)
    """
    engine_path = Path(__file__).parent / 'engine.py'
    
    if not engine_path.exists():
        return (False, f"✗ engine.py not found at {engine_path}")
    
    return (True, f"✓ engine.py module found")


# =============================================================================
# MAIN VALIDATION FUNCTION
# =============================================================================

def perform_full_check(verbose: bool = True) -> bool:
    """
    Perform complete environment validation.
    
    Args:
        verbose: If True, print detailed results
    
    Returns:
        True if all checks pass, False otherwise
    """
    checks = [
        ("Python Version", check_python_version),
        ("Project Metadata", check_project_info),
        ("Required Modules", check_required_modules),
        ("Validator Modules", check_validators),
        ("Pattern Library", check_patterns_module),
        ("Engine Module", check_engine_module),
    ]
    
    results = []
    all_passed = True
    
    for check_name, check_func in checks:
        success, message = check_func()
        results.append((check_name, success, message))
        if not success:
            all_passed = False
    
    if verbose:
        print_check_results(results, all_passed)
    
    return all_passed


def print_check_results(results: List[Tuple[str, bool, str]], all_passed: bool):
    """
    Print formatted check results with colors.
    
    Args:
        results: List of (check_name, success, message) tuples
        all_passed: Whether all checks passed
    """
    # ANSI color codes
    GREEN = '\033[92m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'
    
    print("\n" + "=" * 70)
    print(f"{BOLD}  ENVIRONMENT SELF-CHECK RESULTS{RESET}")
    print("=" * 70 + "\n")
    
    for check_name, success, message in results:
        color = GREEN if success else RED
        print(f"{color}{message}{RESET}")
    
    print("\n" + "=" * 70)
    
    if all_passed:
        print(f"{GREEN}{BOLD}✓ ALL CHECKS PASSED - Environment Ready{RESET}")
    else:
        print(f"{RED}{BOLD}✗ SOME CHECKS FAILED - Please resolve issues{RESET}")
    
    print("=" * 70 + "\n")


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Log Sensitivity Analyzer - Environment Self-Check",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--check',
        action='store_true',
        help='Run environment validation checks'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress output (only use exit code)'
    )
    
    args = parser.parse_args()
    
    if args.check or len(sys.argv) == 1:
        # Run checks
        verbose = not args.quiet
        success = perform_full_check(verbose=verbose)
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
