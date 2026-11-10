import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safeguard import SECRET_PATTERNS, scan_file, scan_text


class TestClaudeCodeSafeguard(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scan_text_detects_openai_key(self):
        fake_key = "sk-" + "a" * 48
        text = f"My key is {fake_key} please don't leak it"
        findings, redacted = scan_text(text, redact=True)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "OpenAI API Key")
        self.assertNotIn(fake_key, redacted)
        self.assertIn("[REDACTED_OPENAI_API_KEY]", redacted)

    def test_scan_text_detects_npm_and_gitlab(self):
        fake_npm = "npm_" + "1" * 36
        fake_gl = "glpat-" + "a" * 20
        text = f"NPM={fake_npm} GITLAB={fake_gl}"
        findings, redacted = scan_text(text, redact=True)
        self.assertEqual(len(findings), 2)
        types = [f[0] for f in findings]
        self.assertIn("NPM Access Token", types)
        self.assertIn("GitLab Personal Access Token", types)

    def test_scan_text_with_allowlist(self):
        dummy_token = "ghp_" + "0" * 36
        text = f"Sample dummy token is {dummy_token}"
        # Without allowlist
        findings, _ = scan_text(text, redact=True)
        self.assertEqual(len(findings), 1)

        # With allowlist
        findings_allowed, redacted = scan_text(text, redact=True, allowlist={dummy_token})
        self.assertEqual(len(findings_allowed), 0)
        self.assertEqual(redacted, text)

    def test_scan_text_clean_content(self):
        text = "Hello world! This is safe non-secret markdown documentation."
        findings, redacted = scan_text(text, redact=True)
        self.assertEqual(len(findings), 0)
        self.assertEqual(text, redacted)

    def test_scan_file_detects_and_redacts(self):
        file_path = Path(self.test_dir) / "config.py"
        fake_gh_pat = "ghp_" + "1" * 36
        file_path.write_text(f"GITHUB_TOKEN = '{fake_gh_pat}'\n", encoding="utf-8")

        clean, findings = scan_file(str(file_path), redact=True, quiet=True)
        self.assertFalse(clean)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "GitHub Personal Access Token (Classic)")

        new_content = file_path.read_text(encoding="utf-8")
        self.assertNotIn(fake_gh_pat, new_content)
        self.assertIn("[REDACTED_GITHUB_PERSONAL_ACCESS_TOKEN_CLASSIC]", new_content)

    def test_scan_env_file_detected(self):
        env_file = Path(self.test_dir) / ".env"
        fake_aws = "AKIA" + "1234567890ABCDEF"
        env_file.write_text(f"AWS_ACCESS_KEY_ID={fake_aws}\n", encoding="utf-8")

        clean, findings = scan_file(str(env_file), redact=False, quiet=True)
        self.assertFalse(clean)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "AWS Access Key ID")



    def test_scan_text_detects_github_app_and_twilio(self):
        fake_ghs = "ghs_" + "x" * 36
        fake_twilio = "AC" + "1" * 32
        text = f"INSTALL_TOKEN={fake_ghs} TWILIO_SID={fake_twilio}"
        findings, redacted = scan_text(text, redact=True)
        self.assertEqual(len(findings), 2)
        types = [f[0] for f in findings]
        self.assertIn("GitHub App Installation Token", types)
        self.assertIn("Twilio Account SID", types)
        self.assertNotIn(fake_ghs, redacted)
        self.assertNotIn(fake_twilio, redacted)

if __name__ == "__main__":
    unittest.main()
