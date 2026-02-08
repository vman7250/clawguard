"""Regex patterns for detecting API keys, secrets, and malicious content."""

import re

# API key patterns - each tuple is (name, compiled regex)
API_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r'sk-ant-[a-zA-Z0-9_-]{20,}')),
    ("OpenAI API key", re.compile(r'sk-proj-[a-zA-Z0-9_-]{20,}')),
    ("OpenAI legacy key", re.compile(r'sk-[a-zA-Z0-9]{40,}')),
    ("Groq API key", re.compile(r'gsk_[a-zA-Z0-9]{20,}')),
    ("xAI/Grok API key", re.compile(r'xai-[a-zA-Z0-9]{20,}')),
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("GitHub PAT", re.compile(r'ghp_[a-zA-Z0-9]{36}')),
    ("GitHub OAuth", re.compile(r'gho_[a-zA-Z0-9]{36}')),
    ("GitLab PAT", re.compile(r'glpat-[a-zA-Z0-9_-]{20,}')),
    ("Slack Bot Token", re.compile(r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+')),
    ("Slack User Token", re.compile(r'xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+')),
    ("Telegram Bot Token", re.compile(r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}')),
    ("Discord Bot Token", re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}')),
    ("OpenRouter API key", re.compile(r'sk-or-v1-[a-f0-9]{64}')),
    ("Google API key", re.compile(r'AIza[0-9A-Za-z_-]{35}')),
    ("Stripe Secret key", re.compile(r'sk_live_[a-zA-Z0-9]{20,}')),
    ("Generic Bearer token", re.compile(r'Bearer\s+[a-zA-Z0-9_.-]{20,}')),
]

# Environment variable reference pattern (${VAR_NAME})
ENV_VAR_PATTERN = re.compile(r'\$\{[A-Z_][A-Z0-9_]*\}')

# Malicious skill patterns
MALICIOUS_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Base64 encoded payload", re.compile(r'(?:base64\s+(?:-d|--decode)|atob|b64decode)\s*[\(\s]')),
    ("Base64 long string", re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')),
    ("curl pipe to shell", re.compile(r'curl\s+.*\|\s*(?:ba)?sh')),
    ("wget pipe to shell", re.compile(r'wget\s+.*\|\s*(?:ba)?sh')),
    ("curl to eval", re.compile(r'curl\s+.*\$\(')),
    ("Python exec/eval", re.compile(r'(?:exec|eval)\s*\(\s*(?:base64|requests|urllib)')),
    ("Paste service URL", re.compile(r'(?:glot\.io|pastebin\.com|paste\.ee|hastebin\.com|dpaste\.com)')),
    ("Password-protected archive", re.compile(r'(?:unzip|7z|tar)\s+.*(?:-p\s*|-P\s*|--password)')),
    ("Reverse shell", re.compile(r'(?:nc|ncat|netcat)\s+.*-e\s+/bin')),
    ("Python reverse shell", re.compile(r'socket\.connect\s*\(\s*\(\s*["\'][\d.]+')),
    ("Download and execute", re.compile(r'(?:curl|wget)\s+.*&&\s*chmod\s+\+x')),
]

# Known C2 IP addresses from ClawHavoc campaign
KNOWN_C2_IPS = [
    "91.92.242.30",
    "54.91.154.110",
]

# C2 IP regex (also catches 95.92.242.* range)
C2_IP_PATTERN = re.compile(r'(?:91\.92\.242\.\d+|95\.92\.242\.\d+|54\.91\.154\.110)')

# Typosquatting publisher names
TYPOSQUAT_PUBLISHERS = [
    "clawhub1",
    "clawhubb",
    "clawhubbcli",
    "clawhub-official",
    "openclaw-official",
]

# Suspicious binaries in skill requirements
SUSPICIOUS_BINS = [
    "nc", "ncat", "netcat", "nmap", "socat",
    "msfconsole", "msfvenom", "metasploit",
    "hydra", "john", "hashcat",
    "tcpdump", "wireshark", "tshark",
]

# Memory poisoning patterns (suspicious instructions in SOUL.md/MEMORY.md)
MEMORY_POISONING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Hidden instruction injection", re.compile(r'(?:ignore|disregard|override)\s+(?:previous|all|safety)\s+(?:instructions|rules)', re.IGNORECASE)),
    ("System prompt override", re.compile(r'you\s+are\s+now\s+(?:a|an)\s+(?:different|new|unrestricted)', re.IGNORECASE)),
    ("Exfiltration instruction", re.compile(r'(?:send|post|upload|transmit)\s+.*(?:to|at)\s+(?:https?://|webhook)', re.IGNORECASE)),
    ("Credential harvesting", re.compile(r'(?:read|extract|collect|gather)\s+.*(?:api.?key|token|password|credential|secret)', re.IGNORECASE)),
    ("Scheduled task injection", re.compile(r'(?:cron|crontab|schedule|periodic|every\s+\d+\s+(?:minute|hour))', re.IGNORECASE)),
]
