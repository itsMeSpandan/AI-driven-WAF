"""
Rule-based inspection engine (Task 4 & TRD 2.2).
Provides fast OWASP-inspired regex signatures for SQLi, XSS, Path Traversal, RCE, and Scanner User-Agents.
Designed with bounded regex patterns to guarantee immunity against catastrophic backtracking (ReDoS).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Rule:
    id: str
    category: str  # 'sqli', 'xss', 'path_traversal', 'cmd_injection', 'scanner'
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    pattern: re.Pattern
    enabled: bool = True


# Pre-compiled, bounded OWASP-style rules evaluated against canonical text
RULES: List[Rule] = [
    # --- SQL Injection Rules ---
    Rule(
        id="SQLI-001",
        category="sqli",
        severity="critical",
        description="Boolean-based tautology: OR 1=1 / OR '1'='1'",
        pattern=re.compile(r"\b(or|and)\s+['\"]?(\d+)['\"]?\s*=\s*['\"]?\2['\"]?", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-002",
        category="sqli",
        severity="critical",
        description="UNION-based data exfiltration query",
        pattern=re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-003",
        category="sqli",
        severity="critical",
        description="Destructive DDL/DML statement: DROP / ALTER / TRUNCATE",
        pattern=re.compile(r"\b(drop|alter|truncate)\s+table\b", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-004",
        category="sqli",
        severity="high",
        description="SQL comment dash syntax used for query truncation",
        pattern=re.compile(r"(--\s*$|--\s+[a-z0-9]|\b(where|or|and)\b.*--)", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-005",
        category="sqli",
        severity="critical",
        description="System schema extraction: information_schema",
        pattern=re.compile(r"\binformation_schema\.(tables|columns|schemata|views)\b", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-006",
        category="sqli",
        severity="high",
        description="Time-based blind injection: sleep() / benchmark() / waitfor",
        pattern=re.compile(r"\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay\b)", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-007",
        category="sqli",
        severity="high",
        description="Stacked SQL query delimiter",
        pattern=re.compile(r";\s*(select|insert|update|delete|drop|declare)\b", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-008",
        category="sqli",
        severity="high",
        description="File system exfiltration via load_file or into outfile",
        pattern=re.compile(r"\b(load_file|into\s+(out|dump)file)\b", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-009",
        category="sqli",
        severity="medium",
        description="SQL hexadecimal literal pattern",
        pattern=re.compile(r"\b0x[0-9a-f]{4,}\b", re.IGNORECASE),
    ),
    Rule(
        id="SQLI-010",
        category="sqli",
        severity="high",
        description="Authentication bypass: admin quote dash",
        pattern=re.compile(r"\badmin['\"]?\s*--", re.IGNORECASE),
    ),

    # --- Cross-Site Scripting (XSS) Rules ---
    Rule(
        id="XSS-001",
        category="xss",
        severity="critical",
        description="Explicit script tag injection",
        pattern=re.compile(r"<\s*script\b", re.IGNORECASE),
    ),
    Rule(
        id="XSS-002",
        category="xss",
        severity="high",
        description="Script closing tag",
        pattern=re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
    ),
    Rule(
        id="XSS-003",
        category="xss",
        severity="high",
        description="HTML onload event handler injection",
        pattern=re.compile(r"\bonload\s*=", re.IGNORECASE),
    ),
    Rule(
        id="XSS-004",
        category="xss",
        severity="high",
        description="HTML onerror event handler injection",
        pattern=re.compile(r"\bonerror\s*=", re.IGNORECASE),
    ),
    Rule(
        id="XSS-005",
        category="xss",
        severity="high",
        description="Interactive event handlers (onclick, onmouseover, onfocus)",
        pattern=re.compile(r"\bon(click|mouse|hover|key|focus|blur|toggle)\s*=", re.IGNORECASE),
    ),
    Rule(
        id="XSS-006",
        category="xss",
        severity="critical",
        description="javascript: pseudo-protocol URI",
        pattern=re.compile(r"javascript\s*:", re.IGNORECASE),
    ),
    Rule(
        id="XSS-007",
        category="xss",
        severity="high",
        description="vbscript: pseudo-protocol URI",
        pattern=re.compile(r"vbscript\s*:", re.IGNORECASE),
    ),
    Rule(
        id="XSS-008",
        category="xss",
        severity="high",
        description="Embedded iframe element tag",
        pattern=re.compile(r"<\s*iframe\b", re.IGNORECASE),
    ),
    Rule(
        id="XSS-009",
        category="xss",
        severity="high",
        description="SVG with embedded event handler",
        pattern=re.compile(r"<\s*svg\b[^>]*\bon[a-z]+\s*=", re.IGNORECASE),
    ),
    Rule(
        id="XSS-010",
        category="xss",
        severity="medium",
        description="Execution of alert(), prompt(), or confirm() modal calls",
        pattern=re.compile(r"\b(alert|prompt|confirm)\s*\(", re.IGNORECASE),
    ),
    Rule(
        id="XSS-011",
        category="xss",
        severity="high",
        description="DOM cookie / location exfiltration reference",
        pattern=re.compile(r"\bdocument\s*\.\s*(cookie|location|domain)\b", re.IGNORECASE),
    ),

    # --- Path Traversal & Local File Inclusion (LFI) ---
    Rule(
        id="TRAV-001",
        category="path_traversal",
        severity="critical",
        description="Directory traversal sequence (../ or ..\\)",
        pattern=re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
    ),
    Rule(
        id="TRAV-002",
        category="path_traversal",
        severity="critical",
        description="Linux sensitive file probe (/etc/passwd, /etc/shadow)",
        pattern=re.compile(r"/etc/(passwd|shadow|hosts|issue)\b", re.IGNORECASE),
    ),
    Rule(
        id="TRAV-003",
        category="path_traversal",
        severity="critical",
        description="Windows system directory probe (system32/cmd.exe)",
        pattern=re.compile(r"[a-z]:\\(windows|winnt)\\system32", re.IGNORECASE),
    ),

    # --- Remote Code Execution (RCE) / Command Injection ---
    Rule(
        id="CMD-001",
        category="cmd_injection",
        severity="critical",
        description="Command shell piping / chaining (; cat / ; whoami / ; id -u)",
        pattern=re.compile(r"(?:;|&&|\|)\s*(cat|ls|whoami|uname|curl|wget|nc|netcat)\b|(?:;|&&|\|)\s*id\s+-[a-z]", re.IGNORECASE),
    ),
    Rule(
        id="CMD-002",
        category="cmd_injection",
        severity="critical",
        description="Direct shell interpreter invocation (/bin/sh, powershell, cmd.exe)",
        pattern=re.compile(r"(\bpowershell\b|\bcmd\.exe\b|/(bin|usr/bin)/(sh|bash)\b)", re.IGNORECASE),
    ),

    # --- Scanner User-Agents & Fingerprinting ---
    Rule(
        id="SCAN-001",
        category="scanner",
        severity="high",
        description="Automated SQL injection scanner: sqlmap",
        pattern=re.compile(r"sqlmap/[0-9.]+", re.IGNORECASE),
    ),
    Rule(
        id="SCAN-002",
        category="scanner",
        severity="medium",
        description="Automated vulnerability scanner (Nikto, Acunetix, Nessus, Nmap)",
        pattern=re.compile(r"\b(nikto|acunetix|nessus|nmap|masscan)\b", re.IGNORECASE),
    ),
    Rule(
        id="SCAN-003",
        category="scanner",
        severity="high",
        description="Sensitive environment and configuration file probes",
        pattern=re.compile(r"(\.env|\.git/config|\.htaccess|aws/credentials)\b", re.IGNORECASE),
    ),
]


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class RuleHit:
    rule_id: str
    category: str
    severity: str
    description: str
    matched_substring: str


def evaluate_rules(canonical_text: str) -> Optional[RuleHit]:
    """
    Evaluates all enabled regex rules against the canonical normalized request text.
    Returns the highest-severity match (first-in-class) or None if clean.
    """
    if not canonical_text:
        return None

    best_hit: Optional[RuleHit] = None
    best_severity_val = 0

    for rule in RULES:
        if not rule.enabled:
            continue

        match = rule.pattern.search(canonical_text)
        if match:
            sev_val = SEVERITY_ORDER.get(rule.severity, 1)
            if sev_val > best_severity_val:
                best_severity_val = sev_val
                best_hit = RuleHit(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    matched_substring=match.group(0),
                )
                if rule.severity == "critical":
                    # Short-circuit on critical severity
                    break

    return best_hit
