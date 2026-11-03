"""
shred_engine.py — Layer 4: Secure File Erasure & Anti-Forensics
==============================================================
Secure File Lifecycle Manager | Week 3–4 Deliverable
Author: [Your Name]
Date:   [Date]

Why normal deletion is insecure:
  When you delete a file with standard tools or `os.remove()`, the operating
  system does NOT delete the actual data from storage sectors. It merely marks
  the entry in the file system table (MFT in NTFS, inode table in ext4) as "free".
  Forensic recovery tools (Recuva, Autopsy, FTK Imager) can easily read the
  residual plaintext until it is overwritten by chance.

What this module does (Data Sanitization & Anti-Forensics):
  1. Multi-pass overwrite (inspired by DoD 5220.22-M 3-pass baseline):
     - Pass 1: Overwrite every byte with zeros (0x00) + force disk sync (fsync)
     - Pass 2: Overwrite every byte with ones (0xFF)  + force disk sync (fsync)
     - Pass 3: Overwrite with cryptographic random bytes (os.urandom) + fsync
  2. Metadata scrambling / renaming:
     - Renames the file to random strings in the same directory before unlinking,
       erasing directory table entry history (file name leakage).
  3. Truncation and unlinking:
     - Shrinks file length to 0 bytes before calling os.remove().
  4. Cryptographic Erasure Certificate:
     - Calculates pre-shred SHA-256 fingerprint, logs shred timestamp, 
       shred method, and audit trail to `shred_audit.log`.

Cybersecurity concepts demonstrated:
  - Data sanitization (NIST SP 800-88 / DoD 5220.22-M)
  - Anti-forensics & residual data remanence prevention
  - File system metadata obfuscation
  - Audit logging & non-repudiation (Erasure Certificate)
"""

import os
import sys
import string
import random
import datetime
import hashlib

# ── Windows UTF-8 fix for standard output ─────────────────────────────────────
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_LOG_FILE = "shred_audit.log"
DEFAULT_PASSES = 3


def compute_file_sha256(file_path: str) -> str:
    """
    Compute SHA-256 hash of a file prior to destruction.
    This provides a fingerprint for the audit certificate.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_random_filename(length: int = 16) -> str:
    """Generate a random alphanumeric filename for metadata obfuscation."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def overwrite_file(file_path: str, passes: int = DEFAULT_PASSES) -> None:
    """
    Perform multi-pass physical overwrite of file contents on disk.

    Why fsync() is vital:
      Operating systems use write caches in RAM to speed up file operations.
      Without os.fsync(), writes may sit in cache and get discarded on unlink,
      leaving the real magnetic/flash sectors untouched. `os.fsync()` forces
      the OS buffer cache to flush directly to physical media.
    """
    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return

    chunk_size = 64 * 1024  # 64 KB buffer

    with open(file_path, "r+b") as f:
        for pass_num in range(1, passes + 1):
            f.seek(0)
            remaining = file_size

            # Determine the pattern for this pass
            if pass_num == 1:
                # Pass 1: All zeros
                pattern_mode = "0x00 (zeros)"
                fill_chunk = b"\x00" * min(chunk_size, file_size)
                while remaining > 0:
                    write_size = min(len(fill_chunk), remaining)
                    f.write(fill_chunk[:write_size])
                    remaining -= write_size
            elif pass_num == 2:
                # Pass 2: All ones
                pattern_mode = "0xFF (ones)"
                fill_chunk = b"\xFF" * min(chunk_size, file_size)
                while remaining > 0:
                    write_size = min(len(fill_chunk), remaining)
                    f.write(fill_chunk[:write_size])
                    remaining -= write_size
            else:
                # Pass 3+: Cryptographic random data
                pattern_mode = "PRNG random bytes"
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(os.urandom(write_size))
                    remaining -= write_size

            # Force flush to physical medium
            f.flush()
            os.fsync(f.fileno())


def secure_shred_file(file_path: str, passes: int = DEFAULT_PASSES, audit_log: str = AUDIT_LOG_FILE) -> dict:
    """
    Securely overwrite, rename, truncate, and delete a file, 
    generating a verifiable Erasure Certificate.

    Args:
        file_path (str): Target file to securely destroy.
        passes    (int): Number of overwrite cycles (default: 3).
        audit_log (str): Path to write the erasure certificate record.

    Returns:
        dict: Detailed Erasure Certificate metadata.

    Raises:
        FileNotFoundError: If target file does not exist.
        PermissionError: If file is locked or read-only.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    abs_path = os.path.abspath(file_path)
    file_size = os.path.getsize(abs_path)
    pre_shred_hash = compute_file_sha256(abs_path)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Step 1: Multi-pass content overwriting with forced disk sync
    overwrite_file(abs_path, passes=passes)

    # Step 2: Truncate file to zero bytes
    with open(abs_path, "w") as f:
        f.truncate(0)

    # Step 3: Metadata scrambling (Directory entry obfuscation)
    # Renaming hides the original filename in file system directory entries
    dir_name = os.path.dirname(abs_path)
    scrambled_name = os.path.join(dir_name, generate_random_filename(20) + ".tmp")
    os.rename(abs_path, scrambled_name)

    # Step 4: Unlink / remove the scrambled file pointer
    os.remove(scrambled_name)

    # Step 5: Issue Erasure Certificate
    cert = {
        "status": "SANITIZED",
        "timestamp": timestamp,
        "original_file": os.path.basename(file_path),
        "original_path": abs_path,
        "size_bytes": file_size,
        "pre_shred_sha256": pre_shred_hash,
        "overwrite_passes": passes,
        "standard": "DoD 5220.22-M 3-Pass Overwrite",
        "certificate_id": hashlib.sha256(f"{abs_path}{timestamp}{pre_shred_hash}".encode()).hexdigest()[:16].upper()
    }

    # Append to persistent audit log
    try:
        with open(audit_log, "a", encoding="utf-8") as log:
            log.write(
                f"[{cert['timestamp']}] CERT-ID: {cert['certificate_id']} | "
                f"FILE: {cert['original_file']} | SIZE: {cert['size_bytes']} bytes | "
                f"PRE-HASH: {cert['pre_shred_sha256']} | PASSES: {cert['overwrite_passes']} | "
                f"STATUS: {cert['status']}\n"
            )
    except Exception as e:
        print(f"[!] Warning: Could not write to audit log: {e}")

    return cert


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python shred_engine.py <file_to_shred> [passes]")
        sys.exit(1)

    target = sys.argv[1]
    num_passes = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PASSES

    try:
        certificate = secure_shred_file(target, passes=num_passes)
        print("=" * 60)
        print("         CERTIFICATE OF SECURE DATA DESTRUCTION             ")
        print("=" * 60)
        for k, v in certificate.items():
            print(f"  {k.replace('_', ' ').title():<20} : {v}")
        print("=" * 60)
        print("[✓] Original file securely shredded and erased.")
    except Exception as err:
        print(f"[✗] Shredding failed: {err}")
        sys.exit(1)
