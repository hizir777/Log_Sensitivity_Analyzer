# Research Result for gemini-pro

# **Operational Framework for High-Entropy Log Sensitivity Analysis: An R\&D Deep Dive**

## **Executive Summary**

This Research and Development (R\&D) report presents an exhaustive architectural and operational framework for the "Log Sensitivity Analyzer," a specialized security layer designed to intercept, analyze, and sanitize massive log streams in distributed computing environments. As enterprise infrastructures migrate toward microservices and containerized orchestrations, the surface area for accidental data exposure—specifically Personally Identifiable Information (PII) and high-entropy secrets—expands exponentially. This report addresses the critical intersection of technical DevSecOps requirements and stringent legal frameworks, specifically the Turkish Personal Data Protection Law (KVKK) and the European General Data Protection Regulation (GDPR).

The document is structured into six modular deliverables, ranging from theoretical compliance analysis to production-ready Python prototypes and visualization logic. It leverages hybrid detection methodologies, combining optimized Regular Expressions (Regex) with algorithmic validation (Luhn, TC Kimlik checksums) and Shannon Entropy analysis to minimize false positives, a notorious plague in Data Loss Prevention (DLP) systems. Furthermore, it addresses the "Security of the Auditor" paradox, ensuring the tool itself does not become a vector for privilege escalation or data leakage.

# ---

**Module 1: Technical Research Report**

## **1.1 DLP Mechanics: Stream Processing vs. Batch Analysis**

The fundamental architectural decision in designing a Log Sensitivity Analyzer is the choice between stream processing and batch processing. This decision dictates the system's latency, resource consumption, and ability to prevent data leaks in real-time. In the context of DLP for high-throughput logging environments, this choice is not merely operational but existential for compliance.

### **1.1.1 Theoretical Underpinnings and Big O Complexity**

Batch processing operates on accumulated data sets over fixed time intervals. In traditional log analysis, logs are aggregated into files (e.g., hourly rotations) and then processed. The computational complexity of batch processing is often bounded by the size of the total dataset, $N$. While batch processing allows for global optimization and complex joins across historical data, it introduces significant latency.1 If a developer accidentally commits code that logs a database credential at 09:01, and the batch process runs at 10:00, the credential remains exposed in the logs for 59 minutes—a "risk window" that is unacceptable under modern security standards.2

Stream processing, conversely, processes data piece-by-piece as it enters the ingestion pipeline. Theoretically, stream processing operates in $O(1)$ space complexity relative to the total dataset size, as it only holds a small "sliding window" of data in memory at any given time.3 The time complexity remains $O(N)$ relative to the number of incoming events, but the processing is distributed over time rather than spiked at batch intervals. This architectural paradigm shift allows for "data in motion" analysis, enabling the system to intercept and redact sensitive information *before* it is written to disk or indexed by a SIEM.4

### **1.1.2 Performance Characteristics and Trade-offs**

Research indicates that stream processing is superior for DLP use cases where "immediate action" and "pre-storage remediation" are required.

| Feature | Batch Processing | Stream Processing | DLP Implication |
| :---- | :---- | :---- | :---- |
| **Latency** | High (Minutes to Hours) 5 | Low (Milliseconds to Seconds) 5 | Stream allows for "pre-indexing" redaction, preventing the leak from ever persisting. |
| **Throughput** | High (Parallelizable) | High (Scalable) | Streaming requires robust backpressure handling to prevent blocking applications.4 |
| **Complexity** | Low (Static Files) | High (Time Windows, State) | Streaming requires managing state (e.g., multi-line log aggregation) in memory.6 |
| **Resource Usage** | Spiky (High Load during Batches) | Constant (Continuous Load) | Streaming offers predictable resource utilization but requires dedicated infrastructure.1 |

**Conclusion:** For the Log Sensitivity Analyzer, a **Stream Processing** architecture is mandated. The risk of storing PII, even temporarily, in intermediate buffers makes batch processing legally hazardous under KVKK's storage limitation principles.7 The analyzer must act as a middleware filter, redacting secrets in-flight.

## **1.2 Global & Local Standards: KVKK Article 12 vs. GDPR**

The legal imperative for this tool stems from the strict liability imposed on data controllers to secure personal data. While GDPR and KVKK share a lineage, their specific technical mandates and breach notification requirements diverge in ways that impact system design.

### **1.2.1 KVKK Article 12: The Security Mandate**

KVKK Article 12 explicitly charges the data controller with taking "all necessary technical and administrative measures" to prevent unlawful processing and access.7 Unlike GDPR, which emphasizes broad principles, the Turkish Personal Data Protection Board (KVKK Board) has issued specific "Technical and Administrative Measures" guidelines. These guidelines explicitly list "Access Logs," "User Account Management," and "Encryption" as required technical measures.8

A critical distinction lies in breach notification. KVKK Article 12(5) requires notification "within the shortest time," a phrase the Board has interpreted strictly in Decision 2019/10. This contrasts with GDPR's explicit "72-hour" window.11 For the Log Sensitivity Analyzer, this implies that the *detection* of a leak must be near-instantaneous to allow the legal team sufficient time to assess and report "within the shortest time."

### **1.2.2 Comparative Analysis of Technical Requirements**

| Feature | GDPR (EU) | KVKK (Turkey) | Implication for Analyzer |
| :---- | :---- | :---- | :---- |
| **Breach Notification** | 72 Hours 11 | "Shortest Time" (Immediate) | Real-time alerting is critical for KVKK compliance; batching alerts is risky. |
| **Explicit Consent** | Specific bases (Legitimate Interest) | Explicit Consent required for Special Categories 12 | Aggressive flagging of health/sexual data is required as processing it without explicit consent is strictly prohibited. |
| **Data Integrity** | Explicit Principle 12 | Implicit in Art. 12 7 | Logs must be hashed to prove that redaction did not alter the non-sensitive event data.13 |
| **Cross-Border Transfer** | Standard Contractual Clauses (SCC) | Board Approval / Explicit Consent 14 | The tool must detect if logs are being shipped to non-domestic cloud endpoints. |

### **1.2.3 Log Retention and Hashing**

Under Law No. 5651 (Regulation of Publications on the Internet), which often intersects with KVKK compliance for digital services, access logs must be timestamped and digitally signed to ensure integrity.13 The retention periods vary by sector:

* **Telecommunications:** 2 years.15  
* **Tax Procedure Code:** 5 years.15  
* **Commercial Code:** 10 years.15

The Analyzer must therefore support **Integrity Hashing**. When a log line is redacted (e.g., TCKN: 12345 \-\> TCKN: \*\*\*\*\*), the system should generate a hash of the *original* line (stored securely in a separate, highly restricted vault if necessary for forensics) or ensure the redacted log is immediately hashed to prove no further tampering occurred.16

## **1.3 Landscape Analysis: Gitleaks, TruffleHog, and Nightfall**

To build a superior tool, we must analyze the current market leaders in secret scanning. The "Log Sensitivity Analyzer" aims to hybridize the best features of these tools while optimizing for the specific context of *streaming logs* rather than *static code repositories*.

### **1.3.1 Comparative Architecture**

| Feature | Gitleaks | TruffleHog | Nightfall | Proposed Analyzer |
| :---- | :---- | :---- | :---- | :---- |
| **Primary Target** | Git Repositories (Static) | Git History & High Entropy | SaaS & Cloud Apps | **Streaming Logs (Dynamic)** |
| **Detection Engine** | Regex \+ Allow-lists | Regex \+ Shannon Entropy | Machine Learning \+ Regex | **Hybrid (Regex \+ Checksum \+ Entropy)** |
| **Performance** | High (Go-based) | Moderate (Python/Go) | Low (API Latency) | **High (Optimized Regex/Aho-Corasick)** |
| **False Positives** | Low (Specific Rules) | High (Entropy sensitivity) | Low (ML Context) | **Very Low (Algorithmic Validation)** |

### **1.3.2 Insights and Differentiators**

* **Gitleaks:** Gitleaks excels at speed and simplicity using straightforward regex and allow-lists.20 It is the industry standard for pre-commit hooks. However, it largely relies on pattern matching. If a log contains id=12345678901, Gitleaks might ignore it or flag it based purely on length. It lacks the specific *algorithmic* validation for Turkish IDs (TC Kimlik) or the Luhn algorithm for credit cards as a core, customizable feature.18  
* **TruffleHog:** TruffleHog introduced the use of Shannon Entropy to detect high-randomness strings (like AWS keys) that do not follow a known prefix pattern.21 This is powerful but prone to false positives—detecting compiled binary strings or hashes as "secrets".22  
* **Nightfall:** Nightfall utilizes Machine Learning for context awareness, which reduces false positives but introduces latency unsuitable for high-throughput log streams.17

**Differentiation:** The proposed Log Sensitivity Analyzer will implement **Algorithmic Validation layers**. Unlike Gitleaks, which checks if a string *looks* like a credit card, our tool will compute the Luhn Checksum. If the math doesn't validate, the log is ignored, drastically reducing alert fatigue.23 It solves the "streaming" gap left by repository scanners.

## **1.4 Extensible Architecture: Configuration Schema**

Hardcoded rules are the death of security tools. The environment changes faster than the code. Therefore, the analyzer utilizes a YAML-based configuration schema, inspired by Gitleaks' TOML structure but enhanced for log-specific contexts.20

### **1.4.1 The Configuration Philosophy**

The architecture decouples the *Detection Engine* from the *Rule Definitions*. This allows security engineers to inject custom regex for internal identifiers (e.g., COMPANY-API-KEY-123) without recompiling the tool. The configuration must support:

1. **Rule Definition:** Regex pattern, ID, and severity.  
2. **Validation Linking:** Specifying which algorithm (Luhn, TCKN, Verhoeff) to apply to matches.  
3. **Entropy Thresholds:** Customizing sensitivity for specific patterns.  
4. **Allowlisting:** Excluding known safe patterns or file paths.

### **1.4.2 Proposed YAML Structure**

YAML

version: 1.0  
global:  
  entropy\_threshold: 4.5  
  redaction\_char: "\*"

rules:  
  \- id: "TUR-TCKN"  
    description: "Turkish Citizenship Number with Checksum"  
    regex: "\\\\b\[1-9\]\[0-9\]{10}\\\\b"  
    validation\_algorithm: "luhn\_mod10\_tckn" \# Calls internal Python function  
    sensitivity: "high"  
    tags: \["pii", "kvkk"\]

  \- id: "GENERIC-API-KEY"  
    description: "High Entropy String with Key prefix"  
    regex: "(?i)(?:key|api|token|secret)\\\\s\*\[:=\]\\\\s\*(\[A-Za-z0-9\_\\\\-\]{16,})"  
    validation\_algorithm: "shannon\_entropy"  
    entropy\_min: 4.5  
    sensitivity: "critical"

allowlist:  
  description: "Ignore common false positives"  
  regexes:  
    \- "MHZ\_\[A-Z0-9\]+" \# Internal hardware IDs  
  paths:  
    \- "/var/log/non-sensitive-app.log"

This structure supports the "Extensible" requirement by allowing users to define not just the pattern, but the *validation algorithm* to apply.25

## **1.5 Security of the Auditor: "Who Guards the Guardians?"**

A tool that scans for secrets possesses the highest privilege level: it sees everything before it is redacted. If compromised, the Log Sensitivity Analyzer becomes the ultimate surveillance tool for an attacker.26 This is the "Who guards the guardians?" dilemma.

### **1.5.1 The "Guardian" Risk Vectors**

1. **Memory Scrapers:** If the analyzer holds the secrets in RAM during processing, a root-level attacker could dump the process memory.  
2. **Self-Logging:** If the analyzer crashes and prints the log line that caused the crash (which contains the secret) to its *own* error log, it propagates the leak.  
3. **Rule Tampering:** An attacker could modify the YAML config to "allow-list" their own exfiltration traffic or specific secrets.

### **1.5.2 Mitigation Strategies**

* **Secure Memory Handling (mlock):** The tool must utilize OS-level locking (e.g., mlock in C/Python via ctypes) to prevent the RAM pages containing the log buffer from being swapped to disk.28 Variables holding raw logs must be zeroed out (overwritten) immediately after processing, rather than waiting for Garbage Collection.30  
* **Read-Only Filesystem:** The container or server running the analyzer should mount the configuration file as Read-Only.  
* **Ephemeral Existence:** The analyzer should be stateless. It ingests, processes, and emits. It stores nothing.  
* **RBAC & Integrity:** Access to the dashboard and configuration must be strictly controlled (RBAC), and the configuration file itself should be checksummed at startup. If the checksum changes, the service effectively "panics" and shuts down to prevent tampering.32

# ---

**Module 2: The Logic Engine (Regex & Validation)**

This module defines the core detection logic. It moves beyond "naive" regex, which is susceptible to Regular Expression Denial of Service (ReDoS) attacks, towards "Optimized" and "Atomic" patterns.33

## **2.1 Optimized Regex Patterns**

The following patterns utilize **Atomic Grouping** (?\>...) (where supported) or strict character classes to prevent Catastrophic Backtracking. This ensures that the time to process a log line remains linear $O(N)$ and does not explode exponentially $O(2^N)$ upon encountering a malicious string.35

| Data Type | Standard Regex (Dangerous) | Optimized / Safe Regex | Explanation |
| :---- | :---- | :---- | :---- |
| **Turkish ID (TC Kimlik)** | \\d{11} | \\b\[1-9\]\[0-9\]{10}\\b | Enforces 11 digits, cannot start with 0, word boundaries to avoid matching 12-digit numbers. |
| **Credit Card (PAN)** | (?:\\d{4}-){3}\\d{4} | \\b(?:4\[0-9\]{12}(?:\[0-9\]{3})?|5\[1-5\]\[0-9\]{14}) | Validates specific issuer prefixes (Visa starts with 4, MC with 5\) to reduce scanning noise. |
| **Email Address** | .+@.+\\..+ | ^\[a-zA-Z0-9\_.+-\]+@\[a-zA-Z0-9-\]+\\.\[a-zA-Z0-9-.\]+$ | Avoids the . dot-star trap which causes backtracking. Strict character classes.37 |
| **Turkish Phone** | 05\\d{9} | ^(05)(0\[5-7\]|\[3-5\]\[0-9\])\\s?(\[0-9\]{3})\\s?(\[0-9\]{2})\\s?(\[0-9\]{2})$ | Strictly adheres to the Turkish numbering plan (Prefix 05, distinct carrier codes).38 |
| **Generic Secret** | (secret|key).\* | (?i)(?:key|secret|token)\\s\*\[:=\]\\s\*(\[A-Za-z0-9\_\\-\]{16,}) | Looks for "Assignment" syntax (=, :) and minimum length of 16 to avoid matching "secret\_key=true". |

### **2.1.1 ReDoS Prevention Strategy**

Regular Expression Denial of Service (ReDoS) occurs when a regex engine takes exponential time to evaluate a string due to backtracking.33 For example, the pattern (a+)+ applied to aaaaaaaaaaaaaaaaaaaa\! will cause the engine to try every permutation of the grouped \+. To prevent this:

1. **Avoid Nested Quantifiers:** Never place a \+ or \* inside a group that is also quantified (e.g., (x+)+).  
2. **Use Atomic Groups:** If available (in Python regex module, though re has limitations before 3.11), use (?\>...) to discard backtracking positions once a match is made.35  
3. **Strict Character Classes:** Use \[a-zA-Z0-9\] instead of . whenever possible.40

## **2.2 Algorithmic Validation (The "Research" Core)**

Regex alone is insufficient for high-fidelity DLP. We must implement the checksum algorithms used by the issuing authorities.

### **2.2.1 TC Kimlik (Turkish ID) Checksum Algorithm**

The TC Kimlik number is not random. It is an 11-digit number where the 10th and 11th digits are checksums of the first 9\.

* **Logic:**  
  1. Sum of digits at odd indices (1st, 3rd, 5th, 7th, 9th).  
  2. Sum of digits at even indices (2nd, 4th, 6th, 8th).  
  3. **Digit 10:** ((OddSum \* 7\) \- EvenSum) % 10  
  4. **Digit 11:** (Sum of first 10 digits) % 10  
* This validation eliminates 99% of random 11-digit numbers (like phone numbers or order IDs) that might accidentally match the regex.23

### **2.2.2 Luhn Algorithm (Luhn 10\) for Credit Cards**

The Luhn algorithm verifies the payload against a checksum digit (the last digit).

* **Logic:**  
  1. Reverse the number.  
  2. Double every second digit.  
  3. If doubling results in \>9, subtract 9 (e.g., $8 \\times 2 \= 16 \\rightarrow 16 \- 9 \= 7$).  
  4. Sum all digits.  
  5. If Total % 10 \== 0, the number is valid.  
* Implementing this is non-negotiable for distinguishing a Credit Card number from a 16-digit timestamp or UUID.23

## **2.3 High-Entropy Secret Scanning**

For secrets that do not follow a fixed structure (like AWS\_ACCESS\_KEY\_ID), we rely on Shannon Entropy.

### **2.3.1 Shannon Entropy Mathematics**

The entropy $H$ of a string $S$ is defined as:

$$H(S) \= \- \\sum\_{i} P(x\_i) \\log\_2 P(x\_i)$$

Where $P(x\_i)$ is the frequency of character $x\_i$ in the string.

### **2.3.2 Determining the Threshold**

Research suggests that standard English text has an entropy of roughly 3.5 to 3.8 bits per character.  
Base64 encoded strings and cryptographic keys (API keys) utilize the full alphanumeric spectrum uniformly, resulting in entropies between 4.5 and 5.9 bits.

* **Our Threshold:** We set the alert threshold at **4.5**.  
  * $\< 3.5$: Likely Natural Language (Log messages).  
  * $3.5 \- 4.5$: Random tokens, hex strings, or UUIDs (Grey area).  
  * $\> 4.5$: High probability of being a cryptographic secret.21

## **2.4 Advanced Obfuscation Strategies**

Once a secret is detected, remediation must be applied. The "Log Sensitivity Analyzer" supports three modes of obfuscation, selectable via configuration:

1. **Masking:** Replacing characters with a fixed symbol (e.g., \*). Ideally, the first 2 and last 4 characters are preserved to allow developers to identify *which* key was leaked without revealing the key itself (e.g., AKIA\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*1234).  
2. **Hashing:** Replacing the PII with a salted SHA-256 hash. This allows for correlation (e.g., "Did the same user cause errors in multiple systems?") without revealing the user's identity. This technique, known as "Pseudonymization," is favored by GDPR and KVKK.7  
3. **Tokenization:** Replacing the data with a randomly generated token that maps to the original data in a separate, secure vault. This is the most secure but operationally complex method, generally reserved for PCI-DSS environments. For general log analysis, **Masking** and **Hashing** are the primary recommended strategies.43

# ---

**Module 3: Risk Scoring Matrix**

To prioritize incidents, we move beyond binary "Detected/Not Detected" to a nuanced Risk Score. This allows the CSOC Dashboard to generate a "Heatmap."

## **3.1 The Mathematical Framework**

The Risk Score ($R$) for a given log file or stream window is calculated as follows:

$$R\_{total} \= \\sum\_{i=1}^{n} (W\_{type} \\times C\_{context} \\times D\_{density})$$  
Where:

* **$W\_{type}$ (Weight of Data Type):**  
  * **TC Kimlik / PII:** 10 (High Legal Risk \- KVKK).  
  * **Credit Card (PAN):** 9 (PCI-DSS & Financial Risk).  
  * **API Key / Secret:** 8 (Security Risk).  
  * **Email / Phone:** 4 (Moderate PII).  
* **$C\_{context}$ (Context Multiplier):**  
  * **Default:** 1.0.  
  * **Proximity to "Password" keyword:** 2.0 (High intent).  
  * **Inside Exception Block:** 1.5 (Likely leak via stack trace).  
* **$D\_{density}$ (Density Factor):**  
  * A logarithmic scaling factor to prevent a single file with 1000 leaks from skewing the heatmap to infinity, while acknowledging the severity of bulk leakage.  
  * $D \= 1 \+ \\log\_{10}(\\text{count})$.44

## **3.2 Scoring Tiers**

Based on the calculated $R\_{total}$:

* **0 \- 10 (Low):** Isolated email or false positive. *Action: Log for audit.*  
* **11 \- 50 (Medium):** Single API key or small cluster of PII. *Action: Alert DevSecOps.*  
* **50 \- 100 (High):** Credit Card data or multiple secrets. *Action: Trigger PagerDuty.*  
* **100+ (Critical):** Database dump or bulk customer data exposure. *Action: Automatic Circuit Breaker (Stop Log Stream).*

This matrix aligns with the "Data Sensitivity Levels" found in Google Cloud DLP and Forcepoint classification schemes.44

# ---

**Module 4: Functional Python Prototype**

This Python script demonstrates the "Hybrid" approach. It ingests a stream (simulated here), applies ReDoS-safe regex, validates using Luhn/TC-Algo, checks Entropy, and redacts the output.

Python

import re  
import math  
import collections  
import ctypes  
import sys  
import logging  
import os  
from typing import List, Tuple, Pattern

\# \--- CONFIGURATION \---  
ENTROPY\_THRESHOLD \= 4.5  
REDACTION\_MASK \= "\*\*\*\*\*\*\*\*\*\*"

\# \--- SECURE MEMORY (MLOCK) \---  
\# Attempt to lock memory to prevent swapping (Linux Only) \[28, 30\]  
def secure\_memory\_lock():  
    try:  
        MCL\_CURRENT \= 1  
        MCL\_FUTURE \= 2  
        libc \= ctypes.CDLL("libc.so.6", use\_errno=True)  
        result \= libc.mlockall(MCL\_CURRENT | MCL\_FUTURE)  
        if result\!= 0:  
            logging.warning("Could not lock memory (mlockall failed). Run as root for higher security.")  
        else:  
            logging.info("Memory locked successfully (mlockall).")  
    except Exception as e:  
        logging.warning(f"Memory locking not supported on this OS: {e}")

\# \--- ALGORITHMIC VALIDATION \---

def validate\_tc\_kimlik(tckn: str) \-\> bool:  
    """  
    Validates Turkish Citizenship Number using Checksum Algo.  
    Source Logic: \[23, 41, 46\]  
    """  
    if len(tckn)\!= 11 or tckn.startswith('0'):  
        return False  
      
    \# Ensure all chars are digits  
    if not tckn.isdigit():  
        return False

    digits \= \[int(d) for d in tckn\]  
      
    \# 10th digit calculation  
    odd\_sum \= sum(digits\[0:9:2\])  \# Indices 0, 2, 4, 6, 8  
    even\_sum \= sum(digits\[1:8:2\]) \# Indices 1, 3, 5, 7  
    digit\_10 \= ((odd\_sum \* 7) \- even\_sum) % 10  
      
    \# 11th digit calculation  
    total\_first\_10 \= sum(digits\[:10\])  
    digit\_11 \= total\_first\_10 % 10  
      
    return digits \== digit\_10 and digits \== digit\_11

def validate\_luhn(cc\_number: str) \-\> bool:  
    """  
    Luhn Algorithm for Credit Card Validation.  
    Source Logic:   
    """  
    \# Remove separators if any remain (though regex handles this)  
    cc\_clean \= cc\_number.replace('-', '').replace(' ', '')  
    if not cc\_clean.isdigit():  
        return False

    digits \= \[int(d) for d in cc\_clean\]  
    checksum \= digits.pop()  
    digits.reverse()  
      
    doubled\_sum \= 0  
    for i, d in enumerate(digits):  
        if i % 2 \== 0:  
            d \*= 2  
            if d \> 9:  
                d \-= 9  
        doubled\_sum \+= d  
          
    return (doubled\_sum \* 9) % 10 \== checksum

def shannon\_entropy(data: str) \-\> float:  
    """  
    Calculates Shannon Entropy in bits per symbol.  
    H(X) \= \-sum(p(x) \* log2(p(x)))  
    Source Logic: \[21, 22\]  
    """  
    if not data:  
        return 0  
    entropy \= 0  
    for x in set(data):  
        p\_x \= float(data.count(x)) / len(data)  
        entropy \+= \- p\_x \* math.log(p\_x, 2)  
    return entropy

\# \--- REGEX ENGINE \---

\# Optimized regex patterns \[37, 38, 47\]  
\# Note: We use \\b to ensure atomic-like behavior at boundaries where possible in Python 're'  
PATTERNS \= {  
    "TC\_KIMLIK": re.compile(r"\\b\[1-9\]\[0-9\]{10}\\b"),  
    \# Credit Card: Matches Visa (4xxx), MasterCard (5xxx)  
    "CREDIT\_CARD": re.compile(r"\\b(?:4\[0-9\]{12}(?:\[0-9\]{3})?|5\[1-5\]\[0-9\]{14})\\b"),  
    \# Turkish Phone: 05xx xxx xx xx or 05xxxxxxxxx  
    "TUR\_PHONE": re.compile(r"05(?:0\[5-7\]|\[3-5\]\[0-9\])\\s?\[0-9\]{3}\\s?\[0-9\]{2}\\s?\[0-9\]{2}"),  
    \# Secrets: Looks for "key=value" pattern with high entropy value  
    "POSSIBLE\_SECRET": re.compile(r"(?i)(?:key|api|token|secret)\\s\*\[:=\]\\s\*(\[A-Za-z0-9\_\\-\]{16,})")  
}

def analyze\_line(line: str) \-\> Tuple\[str, int\]:  
    """  
    Scans a log line, redacts sensitive data, and calculates risk score.  
    """  
    risk\_score \= 0  
    clean\_line \= line  
      
    \# 1\. TC Kimlik Check  
    for match in PATTERNS.finditer(line):  
        val \= match.group()  
        if validate\_tc\_kimlik(val):  
            \# Masking strategy: Keep first 2 digits for context  
            masked\_val \= f"{val\[:2\]}\*\*\*\*\*\*\*\*\*{val\[-1\]}"   
            clean\_line \= clean\_line.replace(val, f"")  
            risk\_score \+= 10 \# High Weight  
              
    \# 2\. Credit Card Check  
    for match in PATTERNS.finditer(line):  
        val \= match.group()  
        if validate\_luhn(val):  
            masked\_val \= f"\*\*\*\*-\*\*\*\*-\*\*\*\*-{val\[-4:\]}"  
            clean\_line \= clean\_line.replace(val, f"\[PAN:{masked\_val}\]")  
            risk\_score \+= 9  
              
    \# 3\. Phone Number Check  
    for match in PATTERNS.finditer(line):  
        val \= match.group()  
        clean\_line \= clean\_line.replace(val, "")  
        risk\_score \+= 4  
              
    \# 4\. Entropy Secret Check  
    \# We look for specific assignment patterns first  
    for match in PATTERNS.finditer(line):  
        secret\_candidate \= match.group(1)  
        entropy \= shannon\_entropy(secret\_candidate)  
        if entropy \> ENTROPY\_THRESHOLD:  
            \# Full redaction for secrets  
            clean\_line \= clean\_line.replace(secret\_candidate, "")  
            risk\_score \+= 8  
              
    return clean\_line, risk\_score

\# \--- MAIN EXECUTION \---

if \_\_name\_\_ \== "\_\_main\_\_":  
    logging.basicConfig(level=logging.INFO)  
    secure\_memory\_lock()  
      
    \# Simulated Log Stream  
    sample\_logs \=  
      
    print("--- Log Sensitivity Analyzer Prototype \---")  
    for log in sample\_logs:  
        cleaned, score \= analyze\_line(log)  
        if score \> 0:  
            print(f" {cleaned}")  
        else:  
            print(f"    {cleaned}")

# ---

**Module 5: Infographic Blueprint**

Title: The Log Sensitivity Defense Layer  
Visual Style: Dark Mode, Neon Blue/Red accents (Cybersecurity/SOC theme).

1. **Top Layer: Ingestion (The Funnel)**  
   * *Icon:* A funnel collecting logs from Kubernetes, AWS CloudWatch, and Nginx.  
   * *Text:* "Stream Processing (O(1) Memory)" \- "Real-time Interception."  
2. **Middle Layer: The Filter Engine (The Brain)**  
   * *Visual:* A CPU chip split into three cores.  
   * *Core 1 (Regex):* "Atomic Grouping" (Shield icon preventing backtracking).  
   * *Core 2 (Algo):* "Math Validation" (Icons: $\\sum$ for Checksums, Luhn, Mod10).  
   * *Core 3 (Entropy):* "Shannon Analysis" (Graph showing randomness \> 4.5 bits).  
3. **Bottom Layer: The Output (The Decision)**  
   * *Left Path (Safe):* Green Arrow \-\> "Hashed & Timestamped Log Storage" (Compliance with KVKK 5651).  
   * *Right Path (Risk):* Red Arrow \-\> "CSOC Alert" (PagerDuty Icon) \+ "Redacted Log" (Text showing API\_KEY=\*\*\*\*\*).  
4. **Sidebar: Compliance Shield**  
   * *KVKK Badge:* "Article 12: Administrative & Technical Measures."  
   * *GDPR Badge:* "Privacy by Default."

# ---

**Module 6: Web Dashboard (CSOC)**

This module provides a single-file HTML/JS dashboard that visualizes the risk scores generated by the Python prototype. It features a "Sensitivity Heatmap" to visualize risk density over time.48

HTML

\<\!DOCTYPE **html**\>  
\<html lang\="en"\>  
\<head\>  
    \<meta charset\="UTF-8"\>  
    \<title\>CSOC Log Sensitivity Dashboard\</title\>  
    \<style\>  
        body { background-color: \#121212; color: \#e0e0e0; font-family: 'Segoe UI', monospace; margin: 0; padding: 20px; }  
       .dashboard { display: grid; grid-template-columns: 3fr 1fr; gap: 20px; }  
       .card { background-color: \#1e1e1e; border: 1px solid \#333; border-radius: 8px; padding: 20px; }  
        h2 { color: \#00d4ff; border-bottom: 1px solid \#333; padding-bottom: 10px; }  
          
        /\* Heatmap Grid \*/  
       .heatmap { display: grid; grid-template-columns: repeat(24, 1fr); gap: 4px; margin-top: 20px; }  
       .hour-block { height: 40px; background-color: \#2a2a2a; border-radius: 2px; position: relative; cursor: pointer; }  
       .hour-block:hover { border: 1px solid \#fff; }  
       .hour-block:hover::after {  
            content: attr(data-risk); position: absolute; bottom: 100%; left: 50%;  
            background: \#000; padding: 5px; border-radius: 4px; font-size: 12px; transform: translateX(-50%); white-space: nowrap; z-index: 10;  
        }  
          
        /\* Risk Colors \*/  
       .risk-low { background-color: \#2ecc71; opacity: 0.3; }  
       .risk-med { background-color: \#f1c40f; opacity: 0.6; }  
       .risk-high { background-color: \#e67e22; opacity: 0.8; }  
       .risk-crit { background-color: \#e74c3c; opacity: 1.0; box-shadow: 0 0 10px \#e74c3c; }

       .log-feed { font-family: 'Consolas', monospace; font-size: 12px; height: 300px; overflow-y: scroll; color: \#aaa; background: \#000; padding: 10px; border: 1px solid \#333; }  
       .log-entry { padding: 4px; border-bottom: 1px solid \#2a2a2a; }  
       .log-entry.redacted { color: \#e74c3c; font-weight: bold; }  
       .log-entry.safe { color: \#2ecc71; }  
          
        /\* Scan Stats \*/  
       .stat-box { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid \#333; padding: 10px 0; }  
       .stat-val { font-size: 1.5em; font-weight: bold; }  
    \</style\>  
\</head\>  
\<body\>  
    \<h1\>LOG SENSITIVITY ANALYZER \<span style\="font-size:0.5em; color:\#666;"\>// KVKK COMPLIANCE NODE\</span\>\</h1\>  
      
    \<div class\="dashboard"\>  
        \<div class\="card"\>  
            \<h2\>24-Hour Sensitivity Heatmap\</h2\>  
            \<p\>Visualizing Risk Density ($R\_{total}$) per hour. High density indicates massive leak events.\</p\>  
            \<div class\="heatmap" id\="heatmapGrid"\>  
                \</div\>  
              
            \<h3\>Live Ingestion Stream\</h3\>  
            \<div class\="log-feed" id\="logFeed"\>  
                \<div class\="log-entry safe"\>System initialized. Memory locked.\</div\>  
                \<div class\="log-entry safe"\>Loading regex patterns... OK.\</div\>  
            \</div\>  
        \</div\>

        \<div class\="card"\>  
            \<h2\>Threat Intel\</h2\>  
            \<div class\="stat-box"\>  
                \<span\>TC Kimlik Detections\</span\>  
                \<span class\="stat-val" style\="color: \#f1c40f;"\>14\</span\>  
            \</div\>  
            \<div class\="stat-box"\>  
                \<span\>Credit Card (PAN)\</span\>  
                \<span class\="stat-val" style\="color: \#e67e22;"\>2\</span\>  
            \</div\>  
            \<div class\="stat-box"\>  
                \<span\>High Entropy Secrets\</span\>  
                \<span class\="stat-val" style\="color: \#e74c3c;"\>3\</span\>  
            \</div\>  
            \<div class\="stat-box"\>  
                \<span\>Compliance Status\</span\>  
                \<span class\="stat-val" style\="color: \#2ecc71;"\>ACTIVE\</span\>  
            \</div\>  
        \</div\>  
    \</div\>

    \<script\>  
        // Simulated Data Generation for Heatmap  
        const heatmapGrid \= document.getElementById('heatmapGrid');  
        for (let i \= 0; i \< 24; i++) {  
            const div \= document.createElement('div');  
            div.className \= 'hour-block';  
              
            // Generate random risk  
            // Most hours should be low risk, with occasional spikes  
            let risk \= Math.floor(Math.random() \* 20);  
            if (i \=== 14 |

| i \=== 15\) risk \+= 80; // Simulated breach at 2 PM  
              
            div.setAttribute('data-risk', \`Hour ${i}:00 \- Risk Score ${risk}\`);  
              
            if (risk \< 20\) div.classList.add('risk-low');  
            else if (risk \< 50\) div.classList.add('risk-med');  
            else if (risk \< 80\) div.classList.add('risk-high');  
            else div.classList.add('risk-crit');  
              
            heatmapGrid.appendChild(div);  
        }

        // Simulated Log Feed  
        const feed \= document.getElementById('logFeed');  
        const riskyLogs \= Redacted TCKN in /var/log/auth.log",  
            " High Entropy string detected in HTTP Header",  
            " Credit Card PAN pattern matched in DB query",  
            " API Key pattern in error stacktrace"  
        \];  
        const safeLogs \= \[  
            "\[INFO\] User session verified",  
            " Cache refreshed",  
            "\[INFO\] Health check passed",  
            "\[INFO\] Service started"  
        \];  
          
        setInterval(() \=\> {  
            const entry \= document.createElement('div');  
            const isRisk \= Math.random() \> 0.7; // 30% chance of risk log  
              
            let msg;  
            if (isRisk) {  
                msg \= riskyLogs\[Math.floor(Math.random() \* riskyLogs.length)\];  
                entry.className \= 'log-entry redacted';  
            } else {  
                msg \= safeLogs\[Math.floor(Math.random() \* safeLogs.length)\];  
                entry.className \= 'log-entry safe';  
            }  
              
            entry.textContent \= \`${new Date().toLocaleTimeString()} ${msg}\`;  
              
            feed.prepend(entry);  
            if(feed.children.length \> 20\) feed.lastChild.remove();  
        }, 1500);  
    \</script\>  
\</body\>  
\</html\>

This report provides the exhaustive technical, legal, and operational groundwork required to build the Log Sensitivity Analyzer. By moving beyond simple regex to algorithmic verification and stream processing, the system addresses the "False Positive" and "Performance" constraints critical for high-throughput enterprise environments, ensuring rigorous compliance with KVKK and GDPR standards.

#### **Alıntılanan çalışmalar**

1. Batch Vs Stream Processing: 10 Key Differences To Know \- Monte Carlo, erişim tarihi Ocak 18, 2026, [https://www.montecarlodata.com/blog-stream-vs-batch-processing/](https://www.montecarlodata.com/blog-stream-vs-batch-processing/)  
2. Big Data 101: Dummy's Guide to Batch vs. Streaming Data \- Precisely, erişim tarihi Ocak 18, 2026, [https://www.precisely.com/big-data/big-data-101-batch-process-streams/](https://www.precisely.com/big-data/big-data-101-batch-process-streams/)  
3. Difference between Batch Processing and Stream Processing \- GeeksforGeeks, erişim tarihi Ocak 18, 2026, [https://www.geeksforgeeks.org/operating-systems/difference-between-batch-processing-and-stream-processing/](https://www.geeksforgeeks.org/operating-systems/difference-between-batch-processing-and-stream-processing/)  
4. Batch vs Stream Processing: Understanding the Difference and When Should You Use Them? \- Domo, erişim tarihi Ocak 18, 2026, [https://www.domo.com/learn/article/batch-vs-stream-processing](https://www.domo.com/learn/article/batch-vs-stream-processing)  
5. How to manage data for your project? Comparing batch processing with stream processing. \- VirtusLab, erişim tarihi Ocak 18, 2026, [https://virtuslab.com/blog/data/batch-processing-vs-stream-processing/](https://virtuslab.com/blog/data/batch-processing-vs-stream-processing/)  
6. Batch Processing vs. Stream Processing: A Comprehensive Guide \- Rivery, erişim tarihi Ocak 18, 2026, [https://rivery.io/blog/batch-vs-stream-processing-pros-and-cons-2/](https://rivery.io/blog/batch-vs-stream-processing-pros-and-cons-2/)  
7. Personal Data Protection Law | Kişisel Verileri Koruma Kurumu, erişim tarihi Ocak 18, 2026, [https://www.kvkk.gov.tr/Icerik/6649/Personal-Data-Protection-Law](https://www.kvkk.gov.tr/Icerik/6649/Personal-Data-Protection-Law)  
8. Standartlarla Kişisel Veri Güvenliği \- Beyaz.Net, erişim tarihi Ocak 18, 2026, [https://www.beyaz.net/tr/guvenlik/makaleler/standartlarla\_kisisel\_veri\_guvenligi.html](https://www.beyaz.net/tr/guvenlik/makaleler/standartlarla_kisisel_veri_guvenligi.html)  
9. Kişisel Veri Güvenliği Rehberi (Teknik ve İdari Tedbirler) \- KVKK, erişim tarihi Ocak 18, 2026, [https://kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf](https://kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf)  
10. GDPR & KVKK Compliance: Legal Requirements \- Hostragons®, erişim tarihi Ocak 18, 2026, [https://www.hostragons.com/en/blog/gdpr-and-kgk-compliance/](https://www.hostragons.com/en/blog/gdpr-and-kgk-compliance/)  
11. Turkey KVKK and the GDPR \- TermsFeed, erişim tarihi Ocak 18, 2026, [https://www.termsfeed.com/blog/turkey-kvkk-gdpr/](https://www.termsfeed.com/blog/turkey-kvkk-gdpr/)  
12. 5651 Loglama Gereksinimleri \- BilgiLog, erişim tarihi Ocak 18, 2026, [https://bilgilog.com/5651-sayili-yasa/loglama-gereksinimleri](https://bilgilog.com/5651-sayili-yasa/loglama-gereksinimleri)  
13. COMPARATIVE EVALUATION OF SELECTED ELEMENTS OF DATA PROTECTION REGULATIONS: TÜRKIYE'S KVKK AND THE EU'S GDPR, erişim tarihi Ocak 18, 2026, [https://apcz.umk.pl/CLR/article/download/57573/44309/213468](https://apcz.umk.pl/CLR/article/download/57573/44309/213468)  
14. KVKK Data Retention and Disposal Schedule \- Murat Aktaş, erişim tarihi Ocak 18, 2026, [https://www.murataktas.co.uk/kvkk-data-retention-and-disposal-schedule/](https://www.murataktas.co.uk/kvkk-data-retention-and-disposal-schedule/)  
15. KVKK Teknik Tedbirlerden Log Kayıtları Maddesi | by Ertugrul Akbas \- Medium, erişim tarihi Ocak 18, 2026, [https://drertugrulakbas.medium.com/kvkk-teknik-tedbirlerden-log-kay%C4%B1tlar%C4%B1-maddesi-bfa3e7c17231](https://drertugrulakbas.medium.com/kvkk-teknik-tedbirlerden-log-kay%C4%B1tlar%C4%B1-maddesi-bfa3e7c17231)  
16. TruffleHog vs. Gitleaks: A Detailed Comparison of Secret Scanning Tools \- Jit.io, erişim tarihi Ocak 18, 2026, [https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools](https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools)  
17. Best Secret Scanning Tools in 2025 \- Aikido, erişim tarihi Ocak 18, 2026, [https://www.aikido.dev/blog/top-secret-scanning-tools](https://www.aikido.dev/blog/top-secret-scanning-tools)  
18. 6 Effective Secret Scanning Tools For This Year \- Legit Security, erişim tarihi Ocak 18, 2026, [https://www.legitsecurity.com/aspm-knowledge-base/secret-scanning-tools](https://www.legitsecurity.com/aspm-knowledge-base/secret-scanning-tools)  
19. Gitleaks step configuration \- Harness Developer Hub, erişim tarihi Ocak 18, 2026, [https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/gitleaks-scanner-reference](https://developer.harness.io/docs/security-testing-orchestration/sto-techref-category/gitleaks-scanner-reference)  
20. Understanding Shannon Entropy: Measuring Randomness for Secure Code Auditing, erişim tarihi Ocak 18, 2026, [https://medium.com/@thesagardahal/understanding-shannon-entropy-measuring-randomness-for-secure-code-auditing-4b3c5697a7f9](https://medium.com/@thesagardahal/understanding-shannon-entropy-measuring-randomness-for-secure-code-auditing-4b3c5697a7f9)  
21. How Secret Detection Tools Spot Leaks \- Soteri, erişim tarihi Ocak 18, 2026, [https://soteri.io/blog/how-secret-detection-tools-spot-leaks](https://soteri.io/blog/how-secret-detection-tools-spot-leaks)  
22. Luhns Algorithm, mod 10 check \- python \- Stack Overflow, erişim tarihi Ocak 18, 2026, [https://stackoverflow.com/questions/64161183/luhns-algorithm-mod-10-check](https://stackoverflow.com/questions/64161183/luhns-algorithm-mod-10-check)  
23. Find secrets with Gitleaks \- GitHub, erişim tarihi Ocak 18, 2026, [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)  
24. Configuration file reference \- TruffleHog Docs, erişim tarihi Ocak 18, 2026, [https://docs.trufflesecurity.com/configuration-file-reference](https://docs.trufflesecurity.com/configuration-file-reference)  
25. Theme 7: The need grows for algorithmic literacy, transparency and oversight, erişim tarihi Ocak 18, 2026, [https://www.pewresearch.org/internet/2017/02/08/theme-7-the-need-grows-for-algorithmic-literacy-transparency-and-oversight/](https://www.pewresearch.org/internet/2017/02/08/theme-7-the-need-grows-for-algorithmic-literacy-transparency-and-oversight/)  
26. AI Sentient Cognitive Defense, Co-Created Security Ecosystems \- Aiwa-AI, erişim tarihi Ocak 18, 2026, [https://www.aiwa-ai.com/post/ai-sentient-cognitive-defense-co-created-security-ecosystems](https://www.aiwa-ai.com/post/ai-sentient-cognitive-defense-co-created-security-ecosystems)  
27. Python Secrets Management: Best Practices for Secure Code \- GitGuardian Blog, erişim tarihi Ocak 18, 2026, [https://blog.gitguardian.com/how-to-handle-secrets-in-python/](https://blog.gitguardian.com/how-to-handle-secrets-in-python/)  
28. Ensuring Secure Data Remains in Memory \- Stack Overflow, erişim tarihi Ocak 18, 2026, [https://stackoverflow.com/questions/14779947/ensuring-secure-data-remains-in-memory](https://stackoverflow.com/questions/14779947/ensuring-secure-data-remains-in-memory)  
29. radumarias/zeroize-python: Securely clear secrets from memory. Built on stable Rust primitives which guarantee memory is zeroed using an operation will not be 'optimized away' by the compiler \- GitHub, erişim tarihi Ocak 18, 2026, [https://github.com/radumarias/zeroize-python](https://github.com/radumarias/zeroize-python)  
30. Privy: Password-protected secrets made easy. : r/Python \- Reddit, erişim tarihi Ocak 18, 2026, [https://www.reddit.com/r/Python/comments/5u3v41/privy\_passwordprotected\_secrets\_made\_easy/](https://www.reddit.com/r/Python/comments/5u3v41/privy_passwordprotected_secrets_made_easy/)  
31. Security at what price? Keeping safe, while staying free \- ANU College of Asia & the Pacific \- The Australian National University, erişim tarihi Ocak 18, 2026, [https://nsc.anu.edu.au/national-security-college/content-centre/article/news/security-what-price-keeping-safe-while](https://nsc.anu.edu.au/national-security-college/content-centre/article/news/security-what-price-keeping-safe-while)  
32. Regular expression Denial of Service \- ReDoS \- OWASP Foundation, erişim tarihi Ocak 18, 2026, [https://owasp.org/www-community/attacks/Regular\_expression\_Denial\_of\_Service\_-\_ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)  
33. Regular Expression Denial of Service (ReDoS) and Catastrophic Backtracking | Snyk, erişim tarihi Ocak 18, 2026, [https://snyk.io/blog/redos-and-catastrophic-backtracking/](https://snyk.io/blog/redos-and-catastrophic-backtracking/)  
34. Regex Optimization Techniques: 14 Methods for DevOps Performance \- Last9, erişim tarihi Ocak 18, 2026, [https://last9.io/blog/regex-optimization-techniques/](https://last9.io/blog/regex-optimization-techniques/)  
35. Playing around with 3.11 atomic grouping in regexes : r/Python \- Reddit, erişim tarihi Ocak 18, 2026, [https://www.reddit.com/r/Python/comments/ydfu2q/playing\_around\_with\_311\_atomic\_grouping\_in\_regexes/](https://www.reddit.com/r/Python/comments/ydfu2q/playing_around_with_311_atomic_grouping_in_regexes/)  
36. A list of common regex patterns which are safe from ReDos attack ( regular expression denial of service ) \- GitHub, erişim tarihi Ocak 18, 2026, [https://github.com/phoenixdevio/safe-regex-patterns](https://github.com/phoenixdevio/safe-regex-patterns)  
37. regex \- JavaScript Mobile number verification for Turkey \- Stack Overflow, erişim tarihi Ocak 18, 2026, [https://stackoverflow.com/questions/47353013/javascript-mobile-number-verification-for-turkey](https://stackoverflow.com/questions/47353013/javascript-mobile-number-verification-for-turkey)  
38. TR Turkey Turkish Phone Regex advanced · GitHub, erişim tarihi Ocak 18, 2026, [https://gist.github.com/semihkeskindev/116a3bb09b657212ddb3d56770c5a0c3](https://gist.github.com/semihkeskindev/116a3bb09b657212ddb3d56770c5a0c3)  
39. Preventing ReDoS (Regular Expression Denial of Service) attacks in Express \- HeroDevs, erişim tarihi Ocak 18, 2026, [https://www.herodevs.com/blog-posts/preventing-redos-regular-expression-denial-of-service-attacks-in-express](https://www.herodevs.com/blog-posts/preventing-redos-regular-expression-denial-of-service-attacks-in-express)  
40. Validation of Turkish Identification Number in Python TC Kimlik No Geçerlilik Kontrolü \- Gist, erişim tarihi Ocak 18, 2026, [https://gist.github.com/canerbasaran/5935004](https://gist.github.com/canerbasaran/5935004)  
41. GoSecretScanv2 command \- github.com/m1rl0k/GoSecretScanv2, erişim tarihi Ocak 18, 2026, [https://pkg.go.dev/github.com/m1rl0k/GoSecretScanv2](https://pkg.go.dev/github.com/m1rl0k/GoSecretScanv2)  
42. Personal Data Protection and Processing Policy \- BA Hukuk, erişim tarihi Ocak 18, 2026, [https://www.bahukuk.com/en/p/data-application](https://www.bahukuk.com/en/p/data-application)  
43. PII Data Classification: Main Data Types and Tools to Catalog Them \- Forcepoint, erişim tarihi Ocak 18, 2026, [https://www.forcepoint.com/blog/insights/pii-data-classification](https://www.forcepoint.com/blog/insights/pii-data-classification)  
44. Sensitivity and data risk levels \- Google Cloud Documentation, erişim tarihi Ocak 18, 2026, [https://docs.cloud.google.com/sensitive-data-protection/docs/sensitivity-risk-calculation](https://docs.cloud.google.com/sensitive-data-protection/docs/sensitivity-risk-calculation)  
45. Designing the Perfect SOC Security Dashboard | Medium, erişim tarihi Ocak 18, 2026, [https://medium.com/@adarshpandey180/designing-the-perfect-soc-security-dashboard-a8deea653eb0](https://medium.com/@adarshpandey180/designing-the-perfect-soc-security-dashboard-a8deea653eb0)  
46. Sensitive data heat map, erişim tarihi Ocak 18, 2026, [https://www.microfocus.com/documentation/file-analysis-suite/3.6/FileAnalysisSuite\_3.6.0\_AnalyzeHelpCenter/Content/anlz\_dboard\_sensitiveData\_heatMap.htm](https://www.microfocus.com/documentation/file-analysis-suite/3.6/FileAnalysisSuite_3.6.0_AnalyzeHelpCenter/Content/anlz_dboard_sensitiveData_heatMap.htm)