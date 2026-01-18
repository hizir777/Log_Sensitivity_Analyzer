# Prompts for perplexity

# RESEARCH PROMPT: Log Sensitivity Analyzer - Forensic R&D Phase

**Persona:** Act as a Senior Cybersecurity Research Scientist and Principal DevSecOps Architect specializing in Data Leakage Prevention (DLP). Your goal is to provide a "Technical Whitepaper" that serves as the foundation for the "Log Sensitivity Analyzer" project.

**Project Context:**
The tool is a high-performance audit solution designed for DevOps, SecOps, and Forensic teams. It scans application/server logs for PII (Turkish TC Kimlik, Credit Cards) and Secrets (API Keys, Tokens). The project emphasizes a "JSON-First" approach, "Self-Check" automation, and "Unix I/O" efficiency.

---

### Phase 1: Compliance & Forensic Mandates (KVKK & GDPR)

* **Legal Deep Dive:** Analyze **KVKK Article 12 (Turkey)** and **GDPR Recital 49**. How do these define the legal requirement for "Proactive Log Auditing"?
* **Privacy by Design:** Identify technical controls required to maintain compliance when an audit tool detects sensitive data (e.g., preventing the tool from logging discovered secrets).

### Phase 2: Algorithmic Precision & PII Detection

* **Mathematical Validation:** Provide formal proofs and Python/Go implementations for **Modulo 11 (Turkish TC Kimlik checksum)** and the **Luhn Algorithm (Credit Cards)**.
* **Regex Optimization:** Research high-performance regex patterns for Turkish IBANs, phone numbers, and emails across various log formats (CSV, Syslog, JSON).

### Phase 3: System Architecture & Terminal Automation

* **Unix I/O & Stream Management:** Based on **Unix I/O architecture (File Descriptors 0/1/2, TTY vs. Pipes)**, explain high-throughput stream analysis. Compare **Python (asyncio)**, **Go (Goroutines)**, and **Rust (Tokio)**.
* **JSON-First Approach:** Define a standardized JSON schema for audit reports and a metadata structure for `project_info.json`.

### Phase 4: Secret Scanning & Risk Modeling

* **Detection Methodologies:** Compare **Gitleaks** vs. **TruffleHog**. Research combining **Shannon Entropy** with "Contextual Proximity" to improve accuracy.
* **Risk Scoring:** Define a mathematical formula for a **Risk Scoring Framework** based on "Leak Density" per KB of data.

### Phase 5: Automation & UI Standards

* **Auto Test Ability (Self-Check):** Research implementation methods for a "Self-Check" mechanism using synthetic "canary logs" during deployment.
* **UI Standard:** Suggest **Streamlit** UI/UX standards featuring "Vibrant Colors" and "Responsive Design."

---

## OUTPUT INSTRUCTIONS (STRICT)

**Please provide your entire response as a single, valid Markdown (.md) file inside a code block.** The Markdown file must include:

1. **A Table of Contents.**
2. **Clear hierarchical headings (`#`, `##`, `###`).**
3. **All mathematical notations rendered in LaTeX.**
4. **A "Sources & Citations" section at the end with valid URLs.**
5. **No conversational filler; only the content of the whitepaper.**