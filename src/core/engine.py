"""
Core Analysis Engine for Log Sensitivity Analyzer.

This module provides the main processing logic for scanning logs, detecting PII,
validating candidates, calculating risk scores, and generating reports.

Compliance: KVKK/GDPR Data Leakage Prevention Standards
Author: Senior Security Engineer - DLP Team
"""

import sys
import json
import os
from pathlib import Path
from typing import List, Dict, Optional, TextIO
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse

# =============================================================================
# AUTO-CONTROL: ENVIRONMENT SELF-CHECK
# =============================================================================

def perform_environment_check() -> bool:
    """
    Perform comprehensive environment validation before execution.
    
    Checks:
    1. Python version compatibility (3.10+)
    2. project_info.json existence and validity
    3. Required module availability
    4. Validator module accessibility
    
    Returns:
        bool: True if all checks pass, exits with error otherwise
    """
    errors = []
    warnings = []
    
    # ═══════════════════════════════════════════════════════════════
    # Check 1: Python Version (3.10+)
    # ═══════════════════════════════════════════════════════════════
    required_version = (3, 10)
    current_version = sys.version_info[:2]
    
    if current_version < required_version:
        errors.append(
            f"Python {required_version[0]}.{required_version[1]}+ required, "
            f"but running {current_version[0]}.{current_version[1]}"
        )
    
    # ═══════════════════════════════════════════════════════════════
    # Check 2: project_info.json
    # ═══════════════════════════════════════════════════════════════
    project_root = Path(__file__).parent.parent.parent
    project_info_path = project_root / "project_info.json"
    
    if not project_info_path.exists():
        errors.append(
            f"Missing project_info.json at {project_info_path}"
        )
    else:
        try:
            with open(project_info_path, 'r') as f:
                project_info = json.load(f)
                # Validate structure
                if 'project' not in project_info:
                    warnings.append("project_info.json missing 'project' section")
                if 'requirements' not in project_info:
                    warnings.append("project_info.json missing 'requirements' section")
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in project_info.json: {e}")
        except Exception as e:
            errors.append(f"Error reading project_info.json: {e}")
    
    # ═══════════════════════════════════════════════════════════════
    # Check 3: Required Modules
    # ═══════════════════════════════════════════════════════════════
    required_modules = [
        're', 'json', 'sys', 'os', 'pathlib', 'dataclasses',
        'datetime', 'argparse', 'math'
    ]
    
    for module_name in required_modules:
        try:
            __import__(module_name)
        except ImportError:
            errors.append(f"Required module '{module_name}' not available")
    
    # ═══════════════════════════════════════════════════════════════
    # Check 4: Validator Modules
    # ═══════════════════════════════════════════════════════════════
    validator_path = Path(__file__).parent.parent / 'validators'
    
    if not validator_path.exists():
        errors.append(f"Validators directory not found: {validator_path}")
    else:
        required_validators = ['tckn_validator.py', 'luhn_validator.py']
        for validator in required_validators:
            if not (validator_path / validator).exists():
                errors.append(f"Missing validator: {validator}")
    
    # ═══════════════════════════════════════════════════════════════
    # Check 5: Patterns Module
    # ═══════════════════════════════════════════════════════════════
    patterns_path = Path(__file__).parent / 'patterns.py'
    if not patterns_path.exists():
        errors.append(f"Missing patterns module: {patterns_path}")
    
    # ═══════════════════════════════════════════════════════════════
    # Report Results
    # ═══════════════════════════════════════════════════════════════
    if errors or warnings:
        print("\n" + "=" * 70, file=sys.stderr)
        print("  ENVIRONMENT CHECK RESULTS", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        
        if errors:
            print("\n❌ ERRORS (blocking execution):", file=sys.stderr)
            for i, error in enumerate(errors, 1):
                print(f"  {i}. {error}", file=sys.stderr)
        
        if warnings:
            print("\n⚠️  WARNINGS (non-blocking):", file=sys.stderr)
            for i, warning in enumerate(warnings, 1):
                print(f"  {i}. {warning}", file=sys.stderr)
        
        print("=" * 70 + "\n", file=sys.stderr)
        
        if errors:
            print("❌ Environment check FAILED. Please resolve errors before continuing.\n",
                  file=sys.stderr)
            sys.exit(1)
    
    # Success message (only if no errors or warnings)
    if not errors and not warnings:
        # Silent success - only report issues
        pass
    
    return True


# Perform check on module load
perform_environment_check()


# Add validators to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'validators'))

from tckn_validator import validate_tckn
from luhn_validator import validate_luhn

# Import patterns from current module
from patterns import (
    DetectionPatterns,
    calculate_shannon_entropy,
    is_high_entropy_secret,
    ENTROPY_THRESHOLD
)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class Finding:
    """Represents a single PII/secret detection finding."""
    type: str                    # e.g., 'tc_kimlik', 'credit_card', 'email'
    value: str                   # Original matched value
    masked_value: str            # Masked representation for display
    line_number: int             # Line number in source
    confidence: float            # Validation confidence (0.0-1.0)
    verified: bool               # Whether validator confirmed authenticity
    risk_weight: float           # Risk weight from pattern definition
    risk_level: str              # Human-readable risk level
    context: str                 # Surrounding context (sanitized)
    entropy: Optional[float] = None  # Shannon entropy if applicable


@dataclass
class ScanSummary:
    """Summary statistics for a scan operation."""
    total_lines: int
    total_matches: int
    verified_matches: int
    risk_score: float
    risk_category: str
    findings_by_type: Dict[str, int]
    scan_duration: float


@dataclass
class ScanResult:
    """Complete scan result with metadata and findings."""
    timestamp: str
    tool_version: str
    compliance_framework: str
    findings: List[Finding]
    summary: ScanSummary


# =============================================================================
# RISK SCORING
# =============================================================================

def calculate_risk_level(weight: float) -> str:
    """
    Convert numeric risk weight to human-readable category.
    
    Args:
        weight: Risk weight (0.0-1.0)
    
    Returns:
        Risk level string: CRITICAL, HIGH, MEDIUM, or LOW
    """
    if weight >= 1.0:
        return "CRITICAL"
    elif weight >= 0.7:
        return "HIGH"
    elif weight >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_overall_risk_score(findings: List[Finding]) -> float:
    """
    Calculate overall risk score based on verified findings.
    
    Research: Risk = Σ(weight_i) capped at 10.0
    
    Args:
        findings: List of verified findings
    
    Returns:
        Risk score (0.0-10.0)
    """
    total_risk = sum(f.risk_weight for f in findings if f.verified)
    return min(10.0, total_risk)


def categorize_risk_score(score: float) -> str:
    """
    Categorize overall risk score.
    
    Args:
        score: Risk score (0.0-10.0)
    
    Returns:
        Category string: CRITICAL, HIGH, MEDIUM, or LOW
    """
    if score >= 5.0:
        return "CRITICAL"
    elif score >= 3.0:
        return "HIGH"
    elif score >= 1.0:
        return "MEDIUM"
    else:
        return "LOW"


# =============================================================================
# MASKING LOGIC
# =============================================================================

def mask_value(value: str, match_type: str) -> str:
    """
    Mask sensitive value for safe display.
    
    Masking preserves format while obscuring actual data:
    - TCKN: 12*********1 (show first 2 and last 1)
    - Credit Card: ****-****-****-1234 (show last 4)
    - Email: u***@example.com (show first char)
    - IBAN: TR**...**26 (show country and last 2)
    - Phone: 05******67 (show prefix and last 2)
    - Secrets: ***[REDACTED]***
    
    Args:
        value: Original value to mask
        match_type: Type of match
    
    Returns:
        Masked representation
    """
    if match_type == 'tc_kimlik':
        if len(value) >= 11:
            return f"{value[:2]}{'*' * 9}{value[-1]}"
        return '*' * len(value)
    
    elif match_type in ['credit_card', 'visa', 'mastercard', 'amex']:
        # Remove any spaces/hyphens first
        clean = value.replace(' ', '').replace('-', '')
        if len(clean) >= 4:
            return f"****-****-****-{clean[-4:]}"
        return '*' * len(value)
    
    elif match_type == 'email':
        if '@' in value:
            user, domain = value.split('@', 1)
            if len(user) > 0:
                return f"{user[0]}***@{domain}"
        return '***@***'
    
    elif match_type == 'iban':
        if len(value) >= 4:
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
        return '*' * len(value)
    
    elif match_type == 'phone':
        if len(value) >= 4:
            # Show first 2 and last 2
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
        return '*' * len(value)
    
    else:  # Secrets and others
        return "***[REDACTED]***"


# =============================================================================
# VALIDATOR INTEGRATION
# =============================================================================

def validate_match(match_type: str, value: str) -> tuple[bool, float]:
    """
    Validate a match using appropriate validator.
    
    Args:
        match_type: Type of pattern match
        value: Value to validate
    
    Returns:
        Tuple of (is_valid, confidence_score)
    """
    # Sanitize value
    clean_value = value.replace(' ', '').replace('-', '')
    
    if match_type == 'tc_kimlik':
        is_valid = validate_tckn(clean_value)
        return (is_valid, 0.99 if is_valid else 0.0)
    
    elif match_type in ['visa', 'mastercard', 'amex', 'credit_card']:
        is_valid = validate_luhn(clean_value)
        return (is_valid, 0.99 if is_valid else 0.0)
    
    else:
        # No validation available, assume valid if matched pattern
        return (True, 0.75)  # Medium confidence (pattern match only)


# =============================================================================
# CORE SCANNER
# =============================================================================

class LogScanner:
    """
    Core log scanning engine with pattern matching and validation.
    """
    
    def __init__(self):
        """Initialize scanner with detection patterns."""
        self.patterns = DetectionPatterns.get_all_patterns()
        self.findings: List[Finding] = []
    
    def scan_line(self, line: str, line_number: int) -> List[Finding]:
        """
        Scan a single log line for PII/secrets.
        
        Args:
            line: Log line to scan
            line_number: Line number in source
        
        Returns:
            List of findings detected in this line
        """
        line_findings = []
        
        # Apply each pattern
        for pattern_key, pattern_info in self.patterns.items():
            matches = pattern_info.pattern.finditer(line)
            
            for match in matches:
                value = match.group(0)
                
                # Skip empty matches
                if not value or len(value.strip()) == 0:
                    continue
                
                # Validate if required
                if pattern_info.requires_validation:
                    verified, confidence = validate_match(
                        pattern_info.name,
                        value
                    )
                else:
                    verified = True
                    confidence = 0.75
                
                # For high-entropy strings, check entropy
                if pattern_key == 'HIGH_ENTROPY_STRING':
                    if not is_high_entropy_secret(value):
                        continue  # Skip low-entropy matches
                    entropy = calculate_shannon_entropy(value)
                else:
                    entropy = None
                
                # Extract context (20 chars before and after, sanitized)
                start = max(0, match.start() - 20)
                end = min(len(line), match.end() + 20)
                context = line[start:match.start()] + "[MATCH]" + line[match.end():end]
                
                # Create finding
                finding = Finding(
                    type=pattern_info.name,
                    value=value,
                    masked_value=mask_value(value, pattern_info.name),
                    line_number=line_number,
                    confidence=confidence,
                    verified=verified,
                    risk_weight=pattern_info.risk_weight,
                    risk_level=calculate_risk_level(pattern_info.risk_weight),
                    context=context.strip(),
                    entropy=entropy
                )
                
                line_findings.append(finding)
        
        return line_findings
    
    def scan_file(self, filepath: str) -> ScanResult:
        """
        Scan an entire log file.
        
        Args:
            filepath: Path to log file
        
        Returns:
            ScanResult object with findings and summary
        """
        start_time = datetime.now()
        self.findings = []
        total_lines = 0
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    total_lines = line_num
                    findings = self.scan_line(line.strip(), line_num)
                    self.findings.extend(findings)
        except FileNotFoundError:
            print(f"Error: File not found: {filepath}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return self._create_result(total_lines, duration)
    
    def scan_stdin(self) -> ScanResult:
        """
        Scan from stdin (pipe/redirect support).
        
        Returns:
            ScanResult object with findings and summary
        """
        start_time = datetime.now()
        self.findings = []
        total_lines = 0
        
        try:
            for line_num, line in enumerate(sys.stdin, 1):
                total_lines = line_num
                findings = self.scan_line(line.strip(), line_num)
                self.findings.extend(findings)
        except KeyboardInterrupt:
            print("\nScan interrupted by user", file=sys.stderr)
        except Exception as e:
            print(f"Error reading stdin: {e}", file=sys.stderr)
            sys.exit(1)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return self._create_result(total_lines, duration)
    
    def _create_result(self, total_lines: int, duration: float) -> ScanResult:
        """Create ScanResult from collected findings."""
        # Count findings by type
        findings_by_type = {}
        for finding in self.findings:
            findings_by_type[finding.type] = findings_by_type.get(finding.type, 0) + 1
        
        # Calculate statistics
        verified_count = sum(1 for f in self.findings if f.verified)
        risk_score = calculate_overall_risk_score(self.findings)
        risk_category = categorize_risk_score(risk_score)
        
        summary = ScanSummary(
            total_lines=total_lines,
            total_matches=len(self.findings),
            verified_matches=verified_count,
            risk_score=risk_score,
            risk_category=risk_category,
            findings_by_type=findings_by_type,
            scan_duration=duration
        )
        
        return ScanResult(
            timestamp=datetime.now().isoformat(),
            tool_version="1.0.0",
            compliance_framework="KVKK-GDPR",
            findings=self.findings,
            summary=summary
        )


# =============================================================================
# OUTPUT FORMATTING
# =============================================================================

def output_json(result: ScanResult, file: TextIO = sys.stdout):
    """
    Output scan results as JSON.
    
    Args:
        result: ScanResult to serialize
        file: Output file handle (default: stdout)
    """
    # Convert to dict (excluding actual values for security)
    output = {
        "scan_metadata": {
            "timestamp": result.timestamp,
            "tool_version": result.tool_version,
            "compliance_framework": result.compliance_framework
        },
        "findings": [
            {
                "type": f.type,
                "masked_value": f.masked_value,
                "line_number": f.line_number,
                "verified": f.verified,
                "confidence": f.confidence,
                "risk_level": f.risk_level,
                "risk_weight": f.risk_weight,
                "context": f.context,
                "entropy": f.entropy
            }
            for f in result.findings
        ],
        "summary": asdict(result.summary)
    }
    
    json.dump(output, file, indent=2)
    file.write('\n')


def output_terminal(result: ScanResult):
    """
    Output colorful terminal report.
    
    Uses ANSI escape codes for colors:
    - RED: Critical findings
    - YELLOW: High findings
    - CYAN: Medium findings
    - GREEN: Low findings
    """
    # ANSI color codes
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    GRAY = '\033[90m'
    
    # Header
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}  LOG SENSITIVITY ANALYZER - SCAN REPORT{RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}\n")
    
    # Summary
    print(f"{BOLD}SCAN SUMMARY{RESET}")
    print(f"  Timestamp:        {result.timestamp}")
    print(f"  Lines Scanned:    {result.summary.total_lines}")
    print(f"  Total Matches:    {result.summary.total_matches}")
    print(f"  Verified Matches: {result.summary.verified_matches}")
    print(f"  Scan Duration:    {result.summary.scan_duration:.3f}s")
    
    # Risk Score
    risk_color = RED if result.summary.risk_score >= 5.0 else YELLOW if result.summary.risk_score >= 3.0 else GREEN
    print(f"\n{BOLD}RISK ASSESSMENT{RESET}")
    print(f"  Risk Score:       {risk_color}{result.summary.risk_score:.2f}/10.0{RESET}")
    print(f"  Risk Category:    {risk_color}{BOLD}{result.summary.risk_category}{RESET}")
    
    # Findings by Type
    if result.summary.findings_by_type:
        print(f"\n{BOLD}FINDINGS BY TYPE{RESET}")
        for finding_type, count in sorted(result.summary.findings_by_type.items(), key=lambda x: x[1], reverse=True):
            print(f"  {finding_type:20s}: {count:3d}")
    
    # Detailed Findings (limit to first 20)
    if result.findings:
        print(f"\n{BOLD}DETAILED FINDINGS (Top 20){RESET}")
        print(f"{GRAY}{'─' * 70}{RESET}")
        
        for i, finding in enumerate(result.findings[:20], 1):
            # Color by risk level
            if finding.risk_level == "CRITICAL":
                color = RED
            elif finding.risk_level == "HIGH":
                color = YELLOW
            elif finding.risk_level == "MEDIUM":
                color = CYAN
            else:
                color = GREEN
            
            print(f"\n{BOLD}[{i}] {finding.type.upper()}{RESET}")
            print(f"    {color}Masked Value:{RESET}  {finding.masked_value}")
            print(f"    Line Number:  {finding.line_number}")
            print(f"    Risk Level:   {color}{finding.risk_level}{RESET}")
            print(f"    Verified:     {'✓ Yes' if finding.verified else '✗ No'}")
            print(f"    Confidence:   {finding.confidence:.0%}")
            if finding.entropy is not None:
                print(f"    Entropy:      {finding.entropy:.2f} bits")
    
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    
    # Recommendations
    if result.summary.risk_score >= 3.0:
        print(f"\n{RED}{BOLD}⚠ RECOMMENDED ACTIONS:{RESET}")
        print(f"{RED}  • Immediately review and sanitize detected PII in logs{RESET}")
        print(f"{RED}  • Rotate any exposed API keys/secrets{RESET}")
        print(f"{RED}  • Implement log filtering at application level{RESET}")
        print(f"{RED}  • Conduct KVKK/GDPR compliance audit{RESET}\n")


# =============================================================================
# MAIN CLI
# =============================================================================

def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Log Sensitivity Analyzer - PII and Secret Detection",
        epilog="Examples:\n"
               "  lsa --scan application.log\n"
               "  cat access.log | lsa --scan -\n"
               "  lsa --scan app.log --json > report.json",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--scan',
        metavar='FILE',
        help='Log file to scan (use "-" for stdin)'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON (default: colorful terminal)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Log Sensitivity Analyzer v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.scan:
        parser.print_help()
        sys.exit(1)
    
    # Create scanner
    scanner = LogScanner()
    
    # Scan input
    if args.scan == '-':
        # Scan from stdin
        result = scanner.scan_stdin()
    else:
        # Scan from file
        result = scanner.scan_file(args.scan)
    
    # Output results
    if args.json:
        output_json(result)
    else:
        output_terminal(result)


if __name__ == "__main__":
    main()
