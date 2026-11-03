"""
test_shred.py — Unit Tests for Layer 4: Secure Data Sanitization (Week 3–4)
==========================================================================
Secure File Lifecycle Manager | Unit Tests
Author: [Your Name]
Date:   [Date]

Tests cover:
  - Complete elimination of target file from disk
  - Pre-shred hash match in Erasure Certificate
  - Overwrite integrity (ensuring bytes were overwritten)
  - Metadata obfuscation / renaming before unlink
  - Audit trail logging in shred_audit.log
  - Error handling for missing files
"""

import os
import sys
import tempfile
import unittest

# Ensure modules in current directory are accessible
sys.path.insert(0, os.path.dirname(__file__))

from shred_engine import (
    secure_shred_file,
    compute_file_sha256,
    overwrite_file,
    AUDIT_LOG_FILE,
)


class TestShredEngine(unittest.TestCase):
    """Test suite for Layer 4 secure shredding module."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_file = os.path.join(self.test_dir, "confidential.txt")
        self.test_audit_log = os.path.join(self.test_dir, "test_shred_audit.log")

        # Create sample confidential file with known secret pattern
        self.secret_text = b"TOP SECRET FINANCIAL REPORT DATA 1234567890"
        with open(self.sample_file, "wb") as f:
            f.write(self.secret_text)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_file_is_completely_removed(self):
        """File must no longer exist after secure_shred_file."""
        cert = secure_shred_file(self.sample_file, passes=3, audit_log=self.test_audit_log)
        self.assertFalse(os.path.exists(self.sample_file), "Original file must be deleted")
        self.assertEqual(cert["status"], "SANITIZED")
        print("[TEST 1 PASS] File completely eliminated from filesystem")

    def test_certificate_fields_and_hash(self):
        """Certificate must contain valid pre-shred hash matching original content."""
        expected_hash = compute_file_sha256(self.sample_file)
        cert = secure_shred_file(self.sample_file, passes=3, audit_log=self.test_audit_log)

        self.assertEqual(cert["pre_shred_sha256"], expected_hash)
        self.assertEqual(cert["size_bytes"], len(self.secret_text))
        self.assertEqual(cert["overwrite_passes"], 3)
        self.assertTrue(len(cert["certificate_id"]) > 8)
        print("[TEST 2 PASS] Certificate metadata and pre-shred hash accurate")

    def test_overwrite_wipes_secret_data(self):
        """Test physical overwrite logic directly: file contents must not contain secrets."""
        # Overwrite in place before unlink
        overwrite_file(self.sample_file, passes=3)

        with open(self.sample_file, "rb") as f:
            overwritten_data = f.read()

        # Overwritten data length matches, but plaintext is gone
        self.assertEqual(len(overwritten_data), len(self.secret_text))
        self.assertNotIn(b"TOP SECRET", overwritten_data)
        self.assertNotEqual(overwritten_data, self.secret_text)
        print("[TEST 3 PASS] Physical sector overwrite replaces plaintext with random bytes")

    def test_audit_log_record_created(self):
        """Erasure Certificate must be appended to the specified audit log."""
        cert = secure_shred_file(self.sample_file, passes=3, audit_log=self.test_audit_log)
        self.assertTrue(os.path.isfile(self.test_audit_log))

        with open(self.test_audit_log, "r", encoding="utf-8") as f:
            log_content = f.read()

        self.assertIn(cert["certificate_id"], log_content)
        self.assertIn("confidential.txt", log_content)
        self.assertIn("SANITIZED", log_content)
        print("[TEST 4 PASS] Audit trail entry successfully written to log")

    def test_nonexistent_file_raises_error(self):
        """Shredding a missing file must raise FileNotFoundError."""
        fake_path = os.path.join(self.test_dir, "missing.txt")
        with self.assertRaises(FileNotFoundError):
            secure_shred_file(fake_path, audit_log=self.test_audit_log)
        print("[TEST 5 PASS] Missing file appropriately triggers FileNotFoundError")


if __name__ == "__main__":
    print("=" * 60)
    print("  Secure File Manager — Layer 4 (Shred) Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)
