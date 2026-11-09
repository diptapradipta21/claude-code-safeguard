#!/usr/bin/env python3
"""
claude-code-safeguard — Zero-Leak Secret Interceptor & Security Sandbox for Claude Code CLI.
Scans prompts, tool calls, and file reads to prevent inadvertent leaking of API keys,
passwords, JWT tokens, AWS credentials, and .env files to LLM contexts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# High-entropy & known API key regex patterns (specific patterns first, generic fallback last)
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"\bghp_[a-zA-Z0-9]{36}\b", "GitHub Personal Access Token (Classic)"),
    (r"\bgithub_pat_[a-zA-Z0-9_]{82}\b", "GitHub Fine-Grained Personal Access Token"),
    (r"\bglpat-[a-zA-Z0-9_\-]{20,}\b", "GitLab Personal Access Token"),
    (r"\bnpm_[a-zA-Z0-9]{36}\b", "NPM Access Token"),
    (r"\b[MN][A-Za-z\d]{23,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b", "Discord Bot Token"),
    (r"\bsk-ant-[a-zA-Z0-9_\-]{80,}\b", "Anthropic API Key"),
    (r"\bsk-ant-admin-[a-zA-Z0-9_\-]{32,}\b", "Anthropic Workspace Key"),
    (r"\bsk-[a-zA-Z0-9]{48}\b", "OpenAI API Key"),
    (r"\bsk-[a-f0-9]{32}\b", "DeepSeek API Key"),
    (r"\bsbp_[a-zA-Z0-9]{40}\b", "Supabase Service Token"),
    (r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b", "SendGrid API Key"),
    (r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
    (r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b", "Telegram Bot Token"),
    (r"\bhf_[a-zA-Z0-9]{34,}\b", "Hugging Face Access Token"),
    (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "Slack Webhook URL"),
    (r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b", "JSON Web Token (JWT)"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID"),
    (r"\bAIza[0-9A-Za-z-_]{35}\b", "Google API Key"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Cryptographic Key"),
    (r"(?i)Bearer\s+([a-zA-Z0-9_\-\.]{25,})", "Bearer Authentication Token"),
    (r"(?i)(api[_-]?key|secret|token|password|passwd|auth)[\s:=]+['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?", "Generic Secret/API Key"),
]


def scan_text(
    text: str,
    redact: bool = True,
    allowlist: Optional[Set[str]] = None
) -> Tuple[List[Tuple[str, str]], str]:
    found_secrets: List[Tuple[str, str]] = []
    sanitized_text = text
    allowed = allowlist or set()

    for pattern, name in SECRET_PATTERNS:
        matches = list(re.finditer(pattern, sanitized_text))
        for m in matches:
            secret_val = m.group(0)
            if secret_val in allowed:
                continue
            found_secrets.append((name, secret_val))
            sanitized_text = sanitized_text.replace(
                secret_val,
                f"[REDACTED_{name.upper().replace(' ', '_').replace('/', '_').replace('(', '').replace(')', '')}]"
            )

    return found_secrets, sanitized_text if redact else text


def scan_file(
    file_path: str,
    redact: bool = False,
    quiet: bool = False,
    allowlist: Optional[Set[str]] = None
) -> Tuple[bool, List[Dict[str, str]]]:
    p = Path(file_path)
    if not p.exists():
        if not quiet:
            print(f"[-] File not found: {file_path}", file=sys.stderr)
        return False, []

    content = p.read_text(encoding="utf-8", errors="ignore")
    secrets, sanitized = scan_text(content, redact=redact, allowlist=allowlist)

    findings: List[Dict[str, str]] = []
    for name, val in secrets:
        preview = val[:8] + "..." + val[-4:] if len(val) > 16 else "[HIDDEN]"
        findings.append({
            "type": name,
            "preview": preview,
            "path": str(p)
        })

    if secrets:
        if not quiet:
            print(f"🚨 [DANGER] Found {len(secrets)} sensitive credentials in {file_path}:")
            for f in findings:
                print(f"   • {f['type']}: {f['preview']}")
        if redact:
            p.write_text(sanitized, encoding="utf-8")
            if not quiet:
                print(f"   [✓] File automatically sanitized & redacted.")
        return False, findings
    else:
        if not quiet:
            print(f"✅ [CLEAN] No leaked credentials detected in {file_path}.")
        return True, []


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-Leak Security Interceptor for Claude Code CLI.")
    parser.add_argument("target", nargs="?", default=".", help="File or directory path to audit for secret leaks")
    parser.add_argument("--redact", action="store_true", help="Automatically redact secrets in-place with safe placeholders")
    parser.add_argument("--check", action="store_true", help="CI/Audit mode: fail with exit 1 if secrets found, no file writes")
    parser.add_argument("--stdin", action="store_true", help="Read input text directly from standard input (pipe mode)")
    parser.add_argument("--json", action="store_true", help="Output audit report as structured JSON")
    parser.add_argument("--exclude-dir", nargs="*", default=[], help="Directory names to ignore during scanning")
    parser.add_argument("--allow", "--allowlist", default="", help="Comma-separated tokens/substrings to exempt from detection")

    args = parser.parse_args()

    allow_set = set(t.strip() for t in args.allow.split(",") if t.strip())

    if args.stdin:
        input_data = sys.stdin.read()
        secrets, clean = scan_text(input_data, redact=True, allowlist=allow_set)
        if secrets and not args.json:
            print(f"[!] Safeguard intercepted {len(secrets)} credentials.", file=sys.stderr)
        if args.json:
            report = {
                "input": "stdin",
                "clean": len(secrets) == 0,
                "findings_count": len(secrets),
                "findings": [{"type": s[0], "preview": s[1][:8] + "..." + s[1][-4:] if len(s[1]) > 16 else "[HIDDEN]"} for s in secrets]
            }
            print(json.dumps(report, indent=2))
        else:
            sys.stdout.write(clean)
        sys.exit(0 if len(secrets) == 0 else 1)

    target_path = Path(args.target)
    quiet_mode = args.json

    excluded_dirs = set(args.exclude_dir) | {"node_modules", ".git", "__pycache__", ".venv", "venv"}

    all_findings: List[Dict[str, str]] = []
    scanned_count = 0
    all_clean = True

    if target_path.is_file():
        scanned_count = 1
        clean, findings = scan_file(str(target_path), redact=args.redact, quiet=quiet_mode, allowlist=allow_set)
        all_clean = clean
        all_findings.extend(findings)
    else:
        for f in target_path.rglob("*"):
            if not f.is_file():
                continue
            # Skip hidden parent directories or explicitly excluded directories
            if any(part.startswith(".") for part in f.parts[:-1]) or any(part in excluded_dirs for part in f.parts):
                continue
            # Skip hidden dotfiles, except .env* files which are common leak vectors
            if f.name.startswith(".") and not f.name.startswith(".env"):
                continue
            scanned_count += 1
            clean, findings = scan_file(str(f), redact=args.redact, quiet=quiet_mode, allowlist=allow_set)
            if not clean:
                all_clean = False
                all_findings.extend(findings)

    if args.json:
        report = {
            "target": str(target_path),
            "files_scanned": scanned_count,
            "findings_count": len(all_findings),
            "clean": all_clean,
            "findings": all_findings
        }
        print(json.dumps(report, indent=2))

    sys.exit(0 if all_clean else 1)


if __name__ == "__main__":
    main()
