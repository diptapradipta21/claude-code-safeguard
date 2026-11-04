# 🛡️ Claude Code Safeguard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Security Tested](https://img.shields.io/badge/Security-Zero%20Leak-red.svg)](#)
[![Claude Code CLI](https://img.shields.io/badge/CLI-Claude%20Code-purple.svg)](https://claude.ai/)

> **Zero-Leak Secret Interceptor & Security Sandbox for Claude Code CLI. Pre-scans files, intercepts tool arguments, and redacts exposed credentials before they enter LLM prompts.**

---

## 💡 The Problem
When using autonomous coding agents, developers frequently ask Claude to analyze `.env` files, read configuration dumps, or inspect logs. AI agents accidentally ingest live private keys, AWS secrets, and database passwords into remote prompt contexts, risking severe credential leaks.

## 🚀 The Solution
`claude-code-safeguard` provides an automated pre-execution defense layer:
- **Catches High-Entropy Keys:** GitHub PATs, Anthropic `sk-ant-*`, OpenAI keys, DeepSeek keys, Supabase tokens, SendGrid credentials, Bearer tokens, AWS keys, Telegram bot tokens, Stripe live secrets, HuggingFace tokens, Slack webhooks, and private RSA keys.
- **Pipe / Pre-Hook Mode:** Intercepts terminal outputs before feeding into Claude.
- **In-Place Redaction:** Safely replaces secrets with harmless `[REDACTED]` tokens.
- **CI / Audit Mode:** Fail builds immediately if secrets are detected with `--check`.
- **Structured JSON Telemetry:** Pipe machine-readable security findings directly to MCP servers or security dashboards with `--json`.

---

## ⚡ Quick Start

```bash
# Scan a directory for credentials
python3 safeguard.py ./my-project

# Auto-sanitize files in-place
python3 safeguard.py ./my-project --redact

# Output structured JSON audit report for CI/CD or agent pipelines
python3 safeguard.py ./my-project --json

# Exclude custom directories (auto-skips node_modules, .venv, .git)
python3 safeguard.py ./my-project --exclude-dir build dist cache

# Run in CI mode (exit code 1 on leak, no file modification)
python3 safeguard.py ./my-project --check

# Pipe terminal output before passing to Claude
cat production.env | python3 safeguard.py --stdin
```

---

## 📄 License
MIT License - Copyright (c) 2026 Fajar Indra Pradipta Gajah.
