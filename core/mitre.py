import re

# ---------------------------------------------------------------------------
# MITRE ATT&CK Tactics and Techniques
# ---------------------------------------------------------------------------

MITRE = {
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
    },
    "SQLI": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
    "XSS": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
    "DOS": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "technique_id": "T1498",
    },
    "ANOMALY": {
        "tactic": "Discovery / Reconnaissance",
        "technique": "Behavioral Anomaly",
        "technique_id": "N/A",
    },
}
# ---------------------------------------------------------------------------
# SQLI and XSS patterns
# ---------------------------------------------------------------------------


SQLI_PATTERNS = [
    r"(?:\%27)|(?:')|(?:\-\-)|(?:\%23)|(?:#)",
    r"\bunion\b.*\bselect\b",
    r"\bor\b\s+1=1",
    r"\bselect\b.+\bfrom\b",
    r"\binformation_schema\b",
    r"\bsleep\(",
]

SQLI_RE = re.compile("|".join(SQLI_PATTERNS), flags=re.IGNORECASE)
SQL_KEYWORDS = (
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "exec",
    "execute",
    "from",
    "where",
    "having",
    "group",
    "order",
    "limit",
    "sleep",
    "benchmark",
    "information_schema",
    "load_file",
    "outfile",
    "into",
    "concat",
    "char",
    "hex",
)
SQL_KEYWORD_RE = re.compile(r"\b(?:" + "|".join(SQL_KEYWORDS) + r")\b", re.IGNORECASE)


XSS_PATTERNS = [
    r"<\s*script\b",
    r"%3c\s*script\b",
    r"javascript\s*:",
    r"%3c\s*img\b[^>]*onerror\s*=",
    r"\bon(?:error|load|click|mouseover|focus|mouseenter|animationstart)\s*=",
    r"document\.cookie",
    r"alert\s*\(",
]

XSS_RE = re.compile("|".join(XSS_PATTERNS), flags=re.IGNORECASE)

XSS_INDICATORS = re.compile(
    r"<\s*script|%3c\s*script|javascript\s*:|onerror\s*=|onload\s*=|"
    r"onclick\s*=|onmouseover\s*=|onfocus\s*=|document\.cookie|alert\s*\(",
    re.IGNORECASE,
)
# ---------------------------------------------------------------------------
# Login paths (used by detectors and feature_engineering; single source of truth)
# ---------------------------------------------------------------------------

LOGIN_PATHS = (
    "/login",
    "/signin",
    "/auth",
    "/auth/login",
    "/admin",
    "/admin/login",
    "/wp-login.php",
    "/wp-admin",
    "/user/login",
    "/account/login",
    "/panel",
)

# ---------------------------------------------------------------------------
# Attack paths
# ---------------------------------------------------------------------------

ATTACK_PATHS = (
    "/admin",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/etc/passwd",
    "/backup",
    "/config",
    "/server-status",
    "/db.sql",
    "/admin.php",
)
