# Prompts for gemini-pro

Optimized Prompt: Log Sensitivity Analyzer - R&D Deep Dive
1. Persona & Strategic Context
Role: Senior Cybersecurity Architect & Principal DevSecOps Engineer.
Expertise: Data Leakage Prevention (DLP), Cryptographic Validation, and Log Analytics.
Mission: You are tasked with conducting an exhaustive R&D phase for "Log Sensitivity Analyzer." This tool is a critical security layer designed to prevent PII and Secret exposure within massive distributed log environments, ensuring compliance with KVKK (Turkey) and GDPR (EU).
2. Comprehensive Task & Research Directives
Perform a deep-tier technical analysis and provide a production-ready foundational framework. Address the following with high-level technical rigor:
A. Core Feature Engineering:
Multi-Layer PII Detection: Develop optimized Regex for Turkish ID (TC Kimlik), Credit Card (PAN), Email, and Phone Numbers.
High-Entropy Secret Scanning: Research methods to identify API Keys, JWTs, and Passwords beyond simple regex (e.g., Shannon Entropy analysis).
Risk-Based Threat Analysis: Create a logic flow that categorizes log files by sensitivity density.
Advanced Obfuscation: Propose masking, hashing, and tokenization strategies for log remediation.
B. Deep Research Questions (The "Deep Research" Core):
DLP Mechanics: Explain the internal mechanics of streaming log analysis vs. batch processing for pattern matching.
Global & Local Standards: Compare industry best practices (NIST, OWASP Logging Cheat Sheet) with specific legal requirements of KVKK Article 12.
Landscape Analysis: Perform a comparative analysis of Gitleaks, TruffleHog, and Nightfall. Focus on their detection engines and false-positive reduction techniques.
Extensible Architecture: Define a YAML-based configuration schema that allows for custom regex injection and exclusion rules.
Security of the Auditor: Analyze the "Who guards the guardians?" problem—how to ensure the tool itself doesn't become a target or a source of leakage.
3. Technical Scope & Constraints
Methodology: Hybrid approach using Optimized Regex + Algorithmic Validation.
Accuracy Requirement: You must include algorithmic checks to eliminate false positives:
TC Kimlik: Modulo 10/11 checksum logic.
Credit Card: Luhn Algorithm ($Luhn\ 10$).
Secrets: Contextual clues (e.g., api_key=, secret: prefixes).
Performance: Suggestions must consider high-throughput log streams (O-notation efficiency).
4. Deliverables & Output Structure
Please format the output into the following distinct modules:
Module 1: Technical Research Report: A comprehensive white-paper style response to the 5 research questions.
Module 2: The Logic Engine (Regex & Validation):
Provide a table of Optimized Regex patterns.
Provide a pseudo-code or Python function for the TC Kimlik Checksum Algorithm.
Module 3: Risk Scoring Matrix: A mathematical framework (e.g., $Score = \sum (Weight \times Occurrences)$) to classify log risk.
Module 4: Functional Python Prototype: A robust, modular boilerplate script demonstrating:
Log ingestion.
Pattern matching with validation.
Redacted/Masked output generation.
Module 5: Infographic Blueprint: A structured text description/layout for an executive infographic.
Module 6: Web Dashboard (HTML/CSS/JS): A "Cyber-Security Operations Center" (CSOC) style single-file dashboard to visualize scan results, featuring a "Sensitivity Heatmap."