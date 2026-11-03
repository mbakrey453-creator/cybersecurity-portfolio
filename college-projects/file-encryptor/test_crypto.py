"""
test_crypto.py — Unit Tests for Layer 1 (Week 1–2)
====================================================
Secure File Lifecycle Manager | Week 1–2 Tests
Author: [Your Name]
Date:   [Date]

Tests cover:
  - Encryption produces a valid .enc file
  - Decryption recovers the original content exactly
  - Wrong password raises an error
  - Tampered .enc file is caught by integrity check
  - Missing hash file is caught before decryption
  - Empty password is rejected

Run with:
    python test_crypto.py
"""

import os
import sys
import tempfile
import unittest

# Ensure we can import crypto_engine from this folder
sys.path.insert(0, os.path.dirname(__file__))

from crypto_engine import (
    encrypt_file,
    decrypt_file,
    hash_file,
    verify_integrity,
    IntegrityError,
    ENC_EXTENSION,
    HASH_EXTENSION,
)


class TestCryptoEngine(unittest.TestCase):
    """Test suite for crypto_engine.py — Layer 1 encryption module."""

    def setUp(self):
        """
        Create a temporary directory and a sample plaintext file
        before each test. Cleaned up automatically via tearDown.
        """
        # tempfile.mkdtemp() creates a real temp folder on disk
        self.test_dir  = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "sample.txt")
        self.password  = "TestPassword@2024!"

        # Write known content to the test file using binary mode + explicit UTF-8
        # (avoids Windows cp1256 codec errors with emoji characters)
        with open(self.test_file, "wb") as f:
            f.write("Hello, this is secret data! SECRET".encode("utf-8"))

    def tearDown(self):
        """Remove all temp files after each test to keep the disk clean."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ──────────────────────────────────────────────────────────
    # TEST 1: Encryption creates the expected files
    # ──────────────────────────────────────────────────────────
    def test_encrypt_creates_files(self):
        """After encrypt_file(), both .enc and .enc.hash must exist."""
        enc_path  = encrypt_file(self.test_file, self.password)
        hash_path = enc_path + HASH_EXTENSION

        self.assertTrue(os.path.isfile(enc_path),  ".enc file should exist")
        self.assertTrue(os.path.isfile(hash_path), ".enc.hash file should exist")
        print("[TEST 1 PASS] Encryption creates .enc and .hash files")

    # ──────────────────────────────────────────────────────────
    # TEST 2: Ciphertext is different from plaintext
    # ──────────────────────────────────────────────────────────
    def test_encrypted_content_is_different(self):
        """The .enc file must not contain the original plaintext."""
        enc_path = encrypt_file(self.test_file, self.password)

        with open(enc_path, "rb") as f:
            encrypted_bytes = f.read()

        original_text = "Hello, this is secret data! 🔐".encode("utf-8")
        self.assertNotIn(original_text, encrypted_bytes,
                         "Plaintext must not appear in the encrypted file")
        print("[TEST 2 PASS] Encrypted file does not contain plaintext")

    # ──────────────────────────────────────────────────────────
    # TEST 3: Decrypt recovers exact original content
    # ──────────────────────────────────────────────────────────
    def test_decrypt_recovers_original(self):
        """Encrypting then decrypting must produce the original file content."""
        enc_path = encrypt_file(self.test_file, self.password)
        dec_path = decrypt_file(enc_path, self.password)

        with open(dec_path, "rb") as f:
            recovered = f.read().decode("utf-8")

        self.assertEqual(recovered, "Hello, this is secret data! SECRET",
                         "Decrypted content must match the original")
        print("[TEST 3 PASS] Decryption recovers exact original content")

    # ──────────────────────────────────────────────────────────
    # TEST 4: Wrong password raises ValueError
    # ──────────────────────────────────────────────────────────
    def test_wrong_password_raises_error(self):
        """Decrypting with the wrong password must raise ValueError."""
        enc_path = encrypt_file(self.test_file, self.password)

        with self.assertRaises(ValueError):
            decrypt_file(enc_path, "WrongPassword!")
        print("[TEST 4 PASS] Wrong password correctly raises ValueError")

    # ──────────────────────────────────────────────────────────
    # TEST 5: Tampered file is detected by integrity check
    # ──────────────────────────────────────────────────────────
    def test_tampered_file_detected(self):
        """
        Modifying even one byte of the .enc file must be caught by
        verify_integrity() and raise IntegrityError.
        """
        enc_path  = encrypt_file(self.test_file, self.password)
        hash_path = enc_path + HASH_EXTENSION

        # Simulate an attacker modifying the encrypted file
        with open(enc_path, "r+b") as f:
            f.seek(30)       # Skip past the salt+nonce header
            f.write(b"\xFF\x00\xAB")  # Overwrite 3 bytes with garbage

        with self.assertRaises(IntegrityError):
            verify_integrity(enc_path, hash_path)
        print("[TEST 5 PASS] Tampered file correctly triggers IntegrityError")

    # ──────────────────────────────────────────────────────────
    # TEST 6: Missing hash file is caught
    # ──────────────────────────────────────────────────────────
    def test_missing_hash_file_caught(self):
        """
        If the .hash file is missing (e.g., deleted by attacker),
        decrypt_file() must raise FileNotFoundError.
        """
        enc_path  = encrypt_file(self.test_file, self.password)
        hash_path = enc_path + HASH_EXTENSION

        # Delete the hash file
        os.remove(hash_path)

        with self.assertRaises(FileNotFoundError):
            decrypt_file(enc_path, self.password)
        print("[TEST 6 PASS] Missing hash file correctly raises FileNotFoundError")

    # ──────────────────────────────────────────────────────────
    # TEST 7: Empty password is rejected
    # ──────────────────────────────────────────────────────────
    def test_empty_password_rejected(self):
        """encrypt_file() must raise ValueError if password is empty."""
        with self.assertRaises(ValueError):
            encrypt_file(self.test_file, "")
        print("[TEST 7 PASS] Empty password correctly raises ValueError")

    # ──────────────────────────────────────────────────────────
    # TEST 8: Two encryptions of the same file produce different output
    # ──────────────────────────────────────────────────────────
    def test_encryption_is_non_deterministic(self):
        """
        Encrypting the same file twice must produce different ciphertext.
        This proves that random salt + nonce are working correctly.
        (If output were identical, it would leak information about the key.)
        """
        enc1 = encrypt_file(self.test_file, self.password)

        # Encrypt a copy to avoid filename collision
        import shutil
        copy_path = self.test_file + ".copy.txt"
        shutil.copy(self.test_file, copy_path)
        enc2 = encrypt_file(copy_path, self.password)

        with open(enc1, "rb") as f1, open(enc2, "rb") as f2:
            data1 = f1.read()
            data2 = f2.read()

        self.assertNotEqual(data1, data2,
                            "Two encryptions of the same file must produce different ciphertext")
        print("[TEST 8 PASS] Non-deterministic encryption confirmed (random salt+nonce)")

    # ──────────────────────────────────────────────────────────
    # TEST 9: SHA-256 hash changes when file content changes
    # ──────────────────────────────────────────────────────────
    def test_hash_changes_on_modification(self):
        """A 1-byte change in a file must produce a completely different SHA-256."""
        hash1 = hash_file(self.test_file)

        # Append a single byte
        with open(self.test_file, "ab") as f:
            f.write(b"\x00")

        hash2 = hash_file(self.test_file)
        self.assertNotEqual(hash1, hash2,
                            "Modifying a file must change its SHA-256 hash")
        print("[TEST 9 PASS] File hash correctly changes on modification (avalanche effect)")


# ─────────────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Secure File Manager — Layer 1 Test Suite")
    print("=" * 60)
    print()
    # verbosity=2 prints each test name as it runs
    unittest.main(verbosity=2)
