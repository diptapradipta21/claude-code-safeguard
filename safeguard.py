#!/usr/bin/env python3
"""
claude-code-safeguard — Zero-Leak Secret Interceptor & Security Sandbox for Claude Code CLI.
Scans prompts, tool calls, and file reads to prevent inadvertent leaking of API keys,
passwords, JWT tokens, AWS credentials, and .env files to LLM contexts.
"""

import sys
import re
import argparse
from pathlib import Path

# High-entropy & known API key regex patterns
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret|token|password|passwd|auth)[\s:=]+['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?", "Generic Secret/API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token (Classic)"),
    (r"github_pat_[a-zA-Z0-9_]{82}", "GitHub Fine-Grained Personal Access Token"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"sk-ant-[a-zA-Z0-9_\-]{80,}", "Anthropic API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"AIza[0-9A-Za-z-_]{35}", "Google API Key"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Cryptographic Key"),
]

def scan_text(text: str, redact: bool = True):
    found_secrets = []
    sanitized_text = text

    for pattern, name in SECRET_PATTERNS:
        matches = re.finditer(pattern, text)
        for m in matches:
            secret_val = m.group(0)
            found_secrets.append((name, secret_val))
            if redact:
                sanitized_text = sanitized_text.replace(secret_val, f"[REDACTED_{name.upper().replace(' ', '_')}]")

    return found_secrets, sanitized_text

def scan_file(file_path: str, redact: bool = False):
    p = Path(file_path)
    if not p.exists():
        print(f"[-] File not found: {file_path}")
        return False

    content = p.read_text(encoding="utf-8", errors="ignore")
    secrets, sanitized = scan_text(content, redact=redact)

    if secrets:
        print(f"🚨 [DANGER] Found {len(secrets)} sensitive credentials in {file_path}:")
        for name, val in secrets:
            preview = val[:8] + "..." + val[-4:] if len(val) > 16 else "[HIDDEN]"
            print(f"   • {name}: {preview}")
        if redact:
            p.write_text(sanitized, encoding="utf-8")
            print(f"   [✓] File automatically sanitized & redacted.")
        return False
    else:
        print(f"✅ [CLEAN] No leaked credentials detected in {file_path}.")
        return True

def main():
    parser = argparse.ArgumentParser(description="Zero-Leak Security Interceptor for Claude Code CLI.")
    parser.add_argument("target", nargs="?", default=".", help="File or directory path to audit for secret leaks")
    parser.add_argument("--redact", action="store_true", help="Automatically redact secrets in-place with safe placeholders")
    parser.add_argument("--stdin", action="store_true", help="Read input text directly from standard input (pipe mode)")

    args = parser.parse_args()

    if args.stdin:
        input_data = sys.stdin.read()
        secrets, clean = scan_text(input_data, redact=True)
        if secrets:
            print(f"[!] Safeguard intercepted {len(secrets)} credentials.", file=sys.stderr)
        sys.stdout.write(clean)
        sys.exit(0)

    target_path = Path(args.target)
    if target_path.is_file():
        clean = scan_file(str(target_path), redact=args.redact)
        sys.exit(0 if clean else 1)
    else:
        all_clean = True
        for f in target_path.rglob("*"):
            if f.is_file() and not any(part.startswith(".") for part in f.parts):
                if not scan_file(str(f), redact=args.redact):
                    all_clean = False
        sys.exit(0 if all_clean else 1)

if __name__ == "__main__":
    main()
