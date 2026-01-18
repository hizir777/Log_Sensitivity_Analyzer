# Prompts for gemini-fast

Log Sensitivity Analyzer - Ultimate Research & Development Prompt
1. Context & Background
You are acting as a Senior Cybersecurity Architect and DevSecOps Engineer. We are developing a specialized audit tool called the "Log Sensitivity Analyzer." The project's goal is to scan application and server logs to detect Personal Identifiable Information (PII)—specifically targeting TC Kimlik (Turkish ID) numbers, Credit Card data, and contact info—as well as Sensitive Secrets like passwords and API tokens. This tool is rooted in Data Leakage Prevention (DLP) concepts.

2. Task & Goal
Perform a deep technical analysis and provide a foundational implementation for this tool. You must address the following features and research questions:
A. Core Features:

PII Detection: Capture personal data (CC, email, phone, TC Kimlik) using optimized Regex.
Secret Scanning: Identify accidentally logged API keys, secrets, and passwords.
Threat Analysis: Report the risk level of various log files based on findings.
Masking Suggestions: Provide examples of how to securely obfuscate sensitive data.
B. Technical Research Questions:

Working Principles: What are the fundamental mechanics of log-based DLP and pattern matching?
Best Practices: What are the industry standards and best practices for log auditing and PII protection?
Competitor Analysis: What are the notable open-source projects or commercial competitors in this space (e.g., Gitleaks, TruffleHog)?
Configuration: What are the critical configuration files and parameters needed for such a tool to be flexible?
Security Considerations: What are the critical security risks to consider when building a tool that handles sensitive log data?
3. Scope & Constraints
Technical Focus: Data Leakage Prevention (DLP).
Primary Methodology: Pattern Matching (Regex) supplemented by validation logic.
Accuracy: Must include methods to reduce false positives (e.g., checksums for TC Kimlik or Luhn for CC).
Compliance: Ensure the logic aligns with GDPR/KVKK standards.
4. Output Format
Please provide the results in the following structure:

Technical Research Report: Detailed answers to the 5 research questions listed in the Task section.
Regex & Logic Library: Optimized patterns for PII and Secrets, including the logic for TC Kimlik validation.
Risk Scoring Model: A framework for classifying log files (Low to Critical).
Functional Prototype: A Python boilerplate script demonstrating the scanning and masking.
Infographic Summary: A text-based layout/description of an infographic that summarizes the research findings.
Web Dashboard (HTML/CSS): A simple, single-file HTML/CSS code snippet to display the analysis findings in a clean web interface.