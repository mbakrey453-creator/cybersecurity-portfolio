"""
cli.py — Command-Line Interface for Week 1–2
=============================================
Secure File Lifecycle Manager | Week 1–2 Deliverable
Author: [Your Name]
Date:   [Date]

This is the user-facing entry point for Week 1–2.
It lets you test Layer 1 (Encrypt/Decrypt) and Layer 2 (Verify)
from the terminal before the GUI is built in later weeks.

Usage:
    python cli.py encrypt <file>
    python cli.py decrypt <file.enc>
    python cli.py verify  <file.enc>
    python cli.py shred   <file>
    python cli.py hash    <any_file>

Examples:
    python cli.py encrypt secret.txt
    python cli.py decrypt secret.txt.enc
    python cli.py verify  secret.txt.enc
    python cli.py shred   secret.txt
"""

import sys
import getpass          # Hides password input in the terminal (no echo)
import os

# Import our crypto engine — all the real logic lives there
from crypto_engine import (
    encrypt_file,
    decrypt_file,
    hash_file,
    verify_integrity,
    IntegrityError,
    ENC_EXTENSION,
    HASH_EXTENSION,
)
from shred_engine import secure_shred_file


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def get_password(confirm: bool = False) -> str:
    """
    Prompt the user for a password securely (input is hidden).

    Args:
        confirm (bool): If True, asks the user to re-enter the password
                        to catch typos (used during encryption).

    Returns:
        str: The entered password.
    """
    password = getpass.getpass("  Enter password: ")
    if not password:
        print("[!] Password cannot be empty.")
        sys.exit(1)

    if confirm:
        # Ask again to make sure the user didn't make a typo
        password2 = getpass.getpass("  Confirm password: ")
        if password != password2:
            print("[!] Passwords do not match. Aborting.")
            sys.exit(1)

    return password


def print_banner():
    """Print a simple ASCII banner to make the CLI look professional."""
    print("=" * 60)
    print("  Secure File Lifecycle Manager — CLI")
    print("  Layer 1: Encrypt | Layer 2: Verify | Layer 4: Shred")
    print("=" * 60)


def print_usage():
    """Print usage instructions."""
    print("\nUsage:")
    print("  python cli.py encrypt <file>       — Encrypt a file")
    print("  python cli.py decrypt <file.enc>   — Decrypt an .enc file")
    print("  python cli.py verify  <file.enc>   — Check if .enc was tampered")
    print("  python cli.py shred   <file>       — Securely destroy file (anti-forensics)")
    print("  python cli.py hash    <file>        — Print SHA-256 hash of any file")
    print()


# ─────────────────────────────────────────────────────────────
# COMMAND HANDLERS
# ─────────────────────────────────────────────────────────────

def cmd_encrypt(file_path: str):
    """
    Handle the 'encrypt' command.

    Flow:
        1. Check file exists.
        2. Prompt for password (with confirmation).
        3. Call encrypt_file() from crypto_engine.
        4. Report success.
    """
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    print(f"\n[~] Encrypting: {file_path}")
    print(f"    Algorithm : AES-256-GCM")
    print(f"    KDF       : PBKDF2-HMAC-SHA256 (480,000 iterations)")
    print()

    password = get_password(confirm=True)

    try:
        output_path = encrypt_file(file_path, password)
        print(f"\n[✓] Done! Encrypted file: {output_path}")
        print(f"    Hash file stored alongside for integrity verification.")
    except Exception as e:
        print(f"\n[✗] Encryption failed: {e}")
        sys.exit(1)


def cmd_decrypt(enc_path: str):
    """
    Handle the 'decrypt' command.

    Security note:
        Integrity is ALWAYS verified before decryption (inside decrypt_file).
        You cannot bypass this step.

    Flow:
        1. Check .enc file exists.
        2. Prompt for password.
        3. Call decrypt_file() — which internally calls verify_integrity() first.
        4. Report success or failure.
    """
    if not os.path.isfile(enc_path):
        print(f"[!] Encrypted file not found: {enc_path}")
        sys.exit(1)

    print(f"\n[~] Decrypting: {enc_path}")
    print(f"    Step 1 will verify file integrity before decryption.\n")

    password = get_password(confirm=False)

    try:
        output_path = decrypt_file(enc_path, password)
        print(f"\n[✓] Done! Decrypted file: {output_path}")
    except IntegrityError as e:
        # Integrity check failed — file was tampered with
        print(f"\n[✗] INTEGRITY VIOLATION:\n{e}")
        sys.exit(1)
    except ValueError as e:
        # Wrong password or corrupted ciphertext
        print(f"\n[✗] Decryption failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[✗] Unexpected error: {e}")
        sys.exit(1)


def cmd_verify(enc_path: str):
    """
    Handle the 'verify' command — check integrity without decrypting.

    This is a standalone integrity check. Useful to confirm a file
    hasn't been tampered with before you decide to decrypt it.

    Flow:
        1. Check .enc and .hash files exist.
        2. Recompute SHA-256 of the .enc file.
        3. Compare against stored .hash value.
        4. Report PASS or FAIL.
    """
    hash_path = enc_path + HASH_EXTENSION

    if not os.path.isfile(enc_path):
        print(f"[!] Encrypted file not found: {enc_path}")
        sys.exit(1)
    if not os.path.isfile(hash_path):
        print(f"[!] Hash file not found: {hash_path}")
        print(f"    Cannot verify without a stored hash.")
        sys.exit(1)

    print(f"\n[~] Verifying integrity of: {enc_path}")

    try:
        verify_integrity(enc_path, hash_path)
        print(f"[✓] File is CLEAN — no tampering detected.")
    except IntegrityError as e:
        print(f"\n[✗] {e}")
        sys.exit(1)


def cmd_hash(file_path: str):
    """
    Handle the 'hash' command — compute and display SHA-256 of any file.

    Educational use: students can verify that even a 1-byte change
    in the file produces a completely different hash (avalanche effect).
    """
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    print(f"\n[~] Computing SHA-256 hash of: {file_path}")
    digest = hash_file(file_path)
    print(f"    SHA-256: {digest}")


def cmd_shred(file_path: str):
    """
    Handle the 'shred' command — securely overwrites and erases the file.
    Anti-forensics sanitization preventing recovery of deleted files.
    """
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    print(f"\n[~] Warning: About to permanently shred: {file_path}")
    print("    This will overwrite sectors 3 times (0x00, 0xFF, random) and unlink the file.")
    confirm = input("    Are you sure you want to proceed? [y/N]: ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("[!] Shredding aborted by user.")
        return

    try:
        cert = secure_shred_file(file_path, passes=3)
        print("\n[✓] Secure Shred Completed!")
        print(f"    Certificate ID : {cert['certificate_id']}")
        print(f"    Timestamp      : {cert['timestamp']}")
        print(f"    Passes         : {cert['overwrite_passes']} ({cert['standard']})")
        print(f"    Pre-shred Hash : {cert['pre_shred_sha256']}")
        print(f"    Audit logged to: shred_audit.log")
    except Exception as e:
        print(f"\n[✗] Shredding failed: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    """
    Parse command-line arguments and dispatch to the correct handler.

    sys.argv layout:
        sys.argv[0] = "cli.py"   (script name)
        sys.argv[1] = command    (encrypt / decrypt / verify / hash / shred)
        sys.argv[2] = file path
    """
    print_banner()

    # Need at least: script + command + file
    if len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    command   = sys.argv[1].lower()
    file_path = sys.argv[2]

    # Dispatch table — maps command strings to handler functions
    commands = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "verify":  cmd_verify,
        "shred":   cmd_shred,
        "hash":    cmd_hash,
    }

    if command not in commands:
        print(f"[!] Unknown command: '{command}'")
        print_usage()
        sys.exit(1)

    # Call the matching handler
    commands[command](file_path)


if __name__ == "__main__":
    main()
