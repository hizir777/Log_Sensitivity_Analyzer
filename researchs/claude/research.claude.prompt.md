# Prompts for claude

<context>
  <role>Senior Cybersecurity Research Scientist & DLP Architect</role>
  <objective>Conduct a comprehensive R&D phase for a "Log Sensitivity Analyzer" (DLP tool).</objective>
  <instruction>DO NOT write any code yet. Focus purely on deep technical and theoretical research.</instruction>
</context>
<research_directives>
  <topic name="DLP Mechanics">
    Analyze the differences between "Static Log Analysis" and "Streaming Log Ingestion." 
    Compare the efficiency of Regex matching versus AST (Abstract Syntax Tree) parsing for high-volume logs.
  </topic>
  
  <topic name="Pattern Validation Logic">
    Deep dive into false-positive mitigation. 
    Explain the mathematical proof behind Luhn Algorithm (for Credit Cards) and Modulo 11 (for Turkish TC Kimlik).
    Research "Contextual Proximity Analysis": How can we differentiate a random 11-digit number from a real TC Kimlik based on surrounding keywords?
  </topic>
  <topic name="Compliance & Legal">
    Analyze KVKK (Turkey) Article 12 and GDPR requirements regarding log auditing. 
    Explain "Privacy by Design" and "Data Minimization" in the context of security logs.
  </topic>
  <topic name="Threat Modeling">
    Identify risks where the analyzer itself could become a target. 
    If the analyzer finds a secret, how should it handle it without creating a secondary leak (The "Auditor's Dilemma")?
  </topic>
  <topic name="Competitive Landscape">
    Perform a comparative analysis of Gitleaks, TruffleHog, and detect-secrets. 
    Focus on their detection engines and how they handle high-entropy strings.
  </topic>
</research_directives>
<output_requirements>
  1. Provide a "Technical Whitepaper" structure.
  2. Use mathematical notations for algorithms.
  3. Detail the architectural standards (JSON-first, Unix I/O) required for this tool.
</output_requirements>