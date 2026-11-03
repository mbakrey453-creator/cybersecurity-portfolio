"""
crypto_engine.py — Layer 1: Encryption Core
=============================================
Secure File Lifecycle Manager | Week 1–2 Deliverable
Author: [Your Name]
Date:   [Date]

This module is the heart of the project. It handles:
  - Key derivation:  PBKDF2-HMAC-SHA256 turns a user password into a 256-bit key
  - Encryption:      AES-256-GCM (Galois/Counter Mode) provides both
                     CONFIDENTIALITY (nobody can read it) and
                     INTEGRITY (any tampering breaks the auth tag)
  - Decryption:      Reverses the process, verifying authenticity first
  - Hashing:         SHA-256 fingerprint of the encrypted file for Layer 2 (Verify)

Output file format (.enc):
  [ 16 bytes SALT ][ 12 bytes NONCE ][ ciphertext ][ 16 bytes AUTH TAG ]

Cybersecurity concepts demonstrated:
  - Symmetric encryption (AES-256)
  - Authenticated Encryption with Associated Data (AEAD)
  - Password-Based Key Derivation (PBKDF2)
  - Cryptographic hashing (SHA-256)
"""

import os
import sys
import hashlib

# ── Windows UTF-8 fix ─────────────────────────────────────────────────────────
# Windows terminals default to a legacy codepage (e.g. cp1256) that can't
# encode Unicode arrows (→) or checkmarks (✓). Reconfiguring stdout/stderr
# to UTF-8 at module load time fixes this cleanly without changing any logic.
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
# ─────────────────────────────────────────────────────────────────────────────

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

SALT_SIZE   = 16    # bytes — random salt fed into PBKDF2 (prevents rainbow tables)
NONCE_SIZE  = 12    # bytes — AES-GCM standard nonce (96-bit)
ITERATIONS  = 480_000  # PBKDF2 iteration count (NIST recommended minimum 2024)
KEY_SIZE    = 32    # bytes — 256-bit key for AES-256

ENC_EXTENSION   = ".enc"   # output encrypted file suffix
HASH_EXTENSION  = ".hash"  # SHA-256 hash file suffix (used by Layer 2 / Verify)


# ─────────────────────────────────────────────────────────────
# KEY DERIVATION
# ─────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a human-readable password using PBKDF2.

    Why PBKDF2?
        A password like "hello123" is too short and predictable to use directly
        as an encryption key. PBKDF2 applies HMAC-SHA256 hundreds of thousands
        of times (iterations), making brute-force attacks extremely slow.

    Args:
        password (str): The user's plaintext password.
        salt     (bytes): A random 16-byte value (unique per encryption).
                          Ensures two identical passwords produce different keys.

    Returns:
        bytes: A 32-byte (256-bit) cryptographic key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),   # Hash function used inside HMAC
        length=KEY_SIZE,             # Output key length: 32 bytes = AES-256
        salt=salt,                   # Random salt — prevents precomputed attacks
        iterations=ITERATIONS,       # Work factor — higher = slower brute force
    )
    # encode() converts the password string to bytes (UTF-8)
    return kdf.derive(password.encode("utf-8"))


# ─────────────────────────────────────────────────────────────
# ENCRYPTION
# ─────────────────────────────────────────────────────────────

def encrypt_file(input_path: str, password: str) -> str:
    """
    Encrypt a file using AES-256-GCM and save it as <filename>.enc.
    Also computes and saves a SHA-256 hash of the encrypted file.

    AES-256-GCM explained:
        - AES: Block cipher, the global encryption standard.
        - 256: Key size in bits — the largest/strongest AES variant.
        - GCM: Mode of operation that adds an authentication tag.
               The tag proves the ciphertext wasn't modified after encryption.
               This is called Authenticated Encryption (AEAD).

    Output layout inside the .enc file:
        [SALT (16)] [NONCE (12)] [CIPHERTEXT (variable)] [AUTH TAG (16)]
        └─ for key ─┘└─ for GCM ─┘└─ actual data ──────┘└─ integrity ─┘

    Args:
        input_path (str): Full path to the plaintext file to encrypt.
        password   (str): User password for key derivation.

    Returns:
        str: Path to the created .enc file.

    Raises:
        FileNotFoundError: If input_path doesn't exist.
        ValueError: If password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")

    # ── Step 1: Read the plaintext file ──────────────────────
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # ── Step 2: Generate random salt and nonce ───────────────
    # os.urandom() uses the OS's cryptographically secure random number generator
    salt  = os.urandom(SALT_SIZE)   # Random every time → unique key every time
    nonce = os.urandom(NONCE_SIZE)  # Random every time → unique encryption stream

    # ── Step 3: Derive the AES key from the password ─────────
    key = derive_key(password, salt)

    # ── Step 4: Encrypt with AES-256-GCM ─────────────────────
    aesgcm = AESGCM(key)
    # encrypt() returns: ciphertext + 16-byte auth tag (appended automatically)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # ── Step 5: Write output file: salt + nonce + cipher+tag ─
    output_path = input_path + ENC_EXTENSION
    with open(output_path, "wb") as f:
        f.write(salt)                  # First 16 bytes
        f.write(nonce)                 # Next 12 bytes
        f.write(ciphertext_with_tag)   # Rest: ciphertext + 16-byte GCM tag

    # ── Step 6: Hash the encrypted file (Layer 2 pre-work) ───
    # We hash the .enc file (not the plaintext) so the Verify layer
    # can detect any tampering of the stored encrypted file.
    file_hash = hash_file(output_path)
    hash_path = output_path + HASH_EXTENSION
    with open(hash_path, "w") as hf:
        hf.write(file_hash)

    print(f"[+] Encrypted  → {output_path}")
    print(f"[+] Hash saved → {hash_path}")
    print(f"[+] SHA-256    : {file_hash}")

    return output_path


# ─────────────────────────────────────────────────────────────
# DECRYPTION
# ─────────────────────────────────────────────────────────────

def decrypt_file(enc_path: str, password: str) -> str:
    """
    Decrypt an .enc file after verifying its SHA-256 hash integrity.

    Security principle: VERIFY-THEN-DECRYPT
        We always check integrity BEFORE attempting decryption.
        This prevents "padding oracle" and other chosen-ciphertext attacks.

    Steps:
        1. Verify the .hash file matches the current .enc file.
        2. Parse salt + nonce from the .enc file header.
        3. Re-derive the same AES key using the password + salt.
        4. AES-GCM decrypt (this also validates the authentication tag).
        5. Write the decrypted plaintext to disk.

    Args:
        enc_path (str): Path to the .enc encrypted file.
        password (str): User password (must match the one used to encrypt).

    Returns:
        str: Path to the decrypted output file.

    Raises:
        FileNotFoundError: If the .enc or .hash file is missing.
        IntegrityError: If the hash check fails (file was tampered).
        cryptography.exceptions.InvalidTag: If GCM auth tag is invalid
                                            (wrong password or corruption).
    """
    if not os.path.isfile(enc_path):
        raise FileNotFoundError(f"Encrypted file not found: {enc_path}")

    # ── Step 1: Verify integrity before decryption ────────────
    hash_path = enc_path + HASH_EXTENSION
    if not os.path.isfile(hash_path):
        raise FileNotFoundError(
            f"Hash file missing: {hash_path}\n"
            "Cannot verify integrity — decryption aborted."
        )

    verify_integrity(enc_path, hash_path)   # Raises IntegrityError on failure

    # ── Step 2: Read and parse the .enc file ──────────────────
    with open(enc_path, "rb") as f:
        salt              = f.read(SALT_SIZE)   # First 16 bytes
        nonce             = f.read(NONCE_SIZE)  # Next  12 bytes
        ciphertext_with_tag = f.read()          # Everything else

    # ── Step 3: Re-derive the same key ────────────────────────
    key = derive_key(password, salt)

    # ── Step 4: Decrypt (GCM also validates the auth tag) ─────
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    except Exception:
        # The InvalidTag exception means either:
        #   a) Wrong password, OR
        #   b) The ciphertext was subtly modified (bypassing our hash check)
        raise ValueError(
            "Decryption failed. Either the password is wrong "
            "or the file has been tampered with."
        )

    # ── Step 5: Write decrypted output ────────────────────────
    # Strip the .enc extension to recover the original filename
    if enc_path.endswith(ENC_EXTENSION):
        output_path = enc_path[: -len(ENC_EXTENSION)]
    else:
        output_path = enc_path + ".decrypted"

    # If a file with that name already exists, add a suffix to avoid overwriting
    if os.path.exists(output_path):
        base, ext = os.path.splitext(output_path)
        output_path = base + "_decrypted" + ext

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted  → {output_path}")
    return output_path


# ─────────────────────────────────────────────────────────────
# HASHING & INTEGRITY (Layer 2 support)
# ─────────────────────────────────────────────────────────────

def hash_file(file_path: str) -> str:
    """
    Compute the SHA-256 hash of a file and return it as a hex string.

    SHA-256 properties that matter here:
        - Deterministic:   Same file → same hash every time.
        - Avalanche effect: 1-bit change → completely different hash.
        - One-way:         You can't reverse a hash to get the file back.

    We read in chunks (instead of all at once) to handle large files
    without running out of memory.

    Args:
        file_path (str): Path to the file to hash.

    Returns:
        str: 64-character hex string (SHA-256 digest).
    """
    sha256 = hashlib.sha256()
    chunk_size = 65_536  # 64 KB chunks — memory-efficient for large files

    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)  # Feed each chunk into the hash accumulator

    return sha256.hexdigest()  # Return the final 256-bit hash as hex


class IntegrityError(Exception):
    """
    Raised when a file's SHA-256 hash doesn't match its stored hash.
    This means the file was modified after encryption.
    """
    pass


def verify_integrity(enc_path: str, hash_path: str) -> bool:
    """
    Compare the current SHA-256 hash of enc_path against the stored hash.

    This implements the "verify-then-decrypt" security principle.
    If an attacker (or ransomware) modified the .enc file after it was
    created, this check will catch it before we even attempt decryption.

    Args:
        enc_path  (str): Path to the encrypted file.
        hash_path (str): Path to the .hash file containing the expected hash.

    Returns:
        bool: True if integrity check passes.

    Raises:
        IntegrityError: If hashes don't match (tampering detected).
    """
    # Read the stored (expected) hash from the .hash file
    with open(hash_path, "r") as hf:
        stored_hash = hf.read().strip()

    # Recompute the hash of the current .enc file
    current_hash = hash_file(enc_path)

    if current_hash != stored_hash:
        raise IntegrityError(
            f"INTEGRITY VIOLATION DETECTED!\n"
            f"  Expected : {stored_hash}\n"
            f"  Got      : {current_hash}\n"
            f"  File     : {enc_path}\n"
            f"  → The file may have been tampered with. Decryption refused."
        )

    print(f"[✓] Integrity check passed for: {os.path.basename(enc_path)}")
    return True
