# Sources for claude

### 1. **KVKK (Turkish Data Protection Law) - Article 12**

Official KVKK website confirms Article 12 states: "The data controller is obliged to take all necessary technical and organizational measures to provide an appropriate level of security" for preventing unlawful processing, preventing unlawful access, and ensuring protection of personal data.

https://www.kvkk.gov.tr/Icerik/6649/Personal-Data-Protection-Law


---

### 2. **GDPR Article 25 - Data Protection by Design and Default**

Article 25 requires controllers to "implement appropriate technical and organisational measures, such as pseudonymisation, which are designed to implement data-protection principles, such as data minimisation, in an effective manner".

https://gdpr-info.eu/art-25-gdpr/

---

### 3. **Luhn Algorithm (Credit Card Validation)**

**Source Found:** The Luhn algorithm, invented by IBM researcher Hans Peter Luhn and patented in 1960, is a checksum formula that works by doubling every second digit from right to left, summing the results, and checking if the total is divisible by 10.

https://en.wikipedia.org/wiki/Luhn_algorithm

---

### 4. **Turkish TC Kimlik Number Validation**

Turkish ID numbers use a specific algorithm where the tenth digit equals (7 × A - B) mod 10, where A is the sum of odd-position digits (1st, 3rd, 5th, 7th, 9th) and B is the sum of even-position digits (2nd, 4th, 6th, 8th), and the eleventh digit is the sum of the first ten digits mod 10.

https://alisentas.com/en/blog/validate-turkish-id/

---

### 5. **Gitleaks - Secret Scanning Tool**

Gitleaks is an open-source tool for detecting secrets like passwords, API keys, and tokens in git repos using regex patterns and entropy analysis, with over 8 million docker downloads and 12k GitHub stars.

https://github.com/gitleaks/gitleaks

---

### 6. **TruffleHog - Credential Verification**

TruffleHog is a secret detection tool that scans diverse environments including S3 buckets, Docker images, and cloud storage, employing complex patterns and entropy analysis, with the ability to verify credentials by actually testing if they work.

https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools

---

### 7. **detect-secrets - Baseline System**

Detect-secrets is an actively maintained open-source project designed for enterprises, with 18 different plugins available including AWS keys, Entropy Strings, Base64 encoding, and Azure Keys, using a baseline system to avoid scanning entire git histories.

https://spectralops.io/blog/top-9-git-secret-scanning-tools/
