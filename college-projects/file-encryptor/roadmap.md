================================================================================
SECURE FILE LIFECYCLE MANAGER — PROGRESS & ROADMAP REPORT
================================================================================
Student Project: Cybersecurity / Data Protection System
Current Stage: Week 1–2 Completed (Environment Setup + Core Crypto Engine)
================================================================================

1. WHAT HAS BEEN BUILT SO FAR (WEEK 1–2 DELIVERABLES)
--------------------------------------------------------------------------------

We have completed the foundational architecture, the core encryption/decryption
engine, an integrity checking mechanism, an automated unit test suite, a CLI 
tool, and an initial functional GUI.

Files implemented inside `SecureFileManager/`:

1. `crypto_engine.py` (Core Cryptographic Engine)
   - Algorithm: AES-256-GCM (Galois/Counter Mode).
     * Provides confidentiality (data encryption) and authenticity/integrity 
       (built-in 16-byte authentication tag).
   - Key Derivation: PBKDF2-HMAC-SHA256.
     * Takes the user's password and a random 16-byte cryptographic salt.
     * Runs 480,000 iterations (NIST standard) to derive a 256-bit (32-byte) key.
     * Defeats dictionary and precomputed rainbow-table attacks.
   - Encrypted File Layout (.enc):
     [ 16 bytes Salt ] + [ 12 bytes Nonce ] + [ Ciphertext ] + [ 16 bytes Auth Tag ]
   - Pre-check Integrity Hashing:
     * Computes a SHA-256 hash of the created .enc file and writes it to a 
       companion `.enc.hash` file.
   - Decryption & Integrity Verification:
     * Follows the "Verify-then-Decrypt" security model: re-hashes the .enc file 
       and verifies it against the stored `.hash` file before allowing AES 
       decryption to proceed.
     * Catches tampering or corruption before the cipher logic is executed.

2. `cli.py` (Command-Line Interface)
   - Fully interactive terminal interface with silent/masked password input.
   - Commands available:
     * `python -X utf8 cli.py encrypt <file>`
     * `python -X utf8 cli.py decrypt <file.enc>`
     * `python -X utf8 cli.py verify  <file.enc>`
     * `python -X utf8 cli.py hash    <file>`

3. `test_crypto.py` (Comprehensive Automated Test Suite)
   - 9 automated unit tests verifying edge cases and security properties:
     * File generation (.enc and .hash creation).
     * Plaintext absence (ciphertext does not contain raw data).
     * Clean byte-for-byte decryption recovery.
     * Rejection of incorrect passwords.
     * Detection of corrupted/tampered bytes (triggers IntegrityError).
     * Detection of missing companion hash files.
     * Empty password validation rejection.
     * Non-deterministic encryption (random salt + nonce ensure different 
       ciphertext every run even for identical plaintexts).
     * SHA-256 avalanche effect (1-byte alteration drastically shifts digest).
   - Status: All 9/9 unit tests passing.

4. `gui.py` (Functional Desktop Prototype)
   - Built with Python's native `tkinter` library (zero extra UI dependencies).
   - Styled with a minimalist, raw dark-mode terminal layout.
   - Real-time event logging area and status indicator.
   - Background threading to prevent GUI freezing during intensive PBKDF2 hashing.

================================================================================
2. WHAT IS PLANNED FOR THE REMAINING WEEKS
================================================================================

The overall project spans 4 security layers that protect files across their
entire lifecycle. Here is the scheduled implementation roadmap:

--- WEEK 3–4: LAYER 4 — SECURE SHREDDING (DATA SANITIZATION) -------------------
- What it does:
  * Permanently destroys the original plaintext file once it has been encrypted.
- Why standard deletion fails:
  * Standard OS deletion (`os.remove()`) only frees inode/pointer references; the 
    raw bytes remain readable on disk sectors via forensic recovery tools.
- Technical implementation planned:
  * Multi-pass file overwriting (3 passes: e.g., zeros, ones, pseudorandom bytes).
  * Random file renaming before unlinking to obfuscate directory table metadata.
  * Generation of an "Erasure Certificate" log entry verifying secure wipe.

--- WEEK 5–6: LAYER 3 — FILE INTEGRITY MONITOR (FIM) ---------------------------
- What it does:
  * Real-time folder watchdog to alert against tampering, unauthorized changes, 
    or ransomware modification.
- Technical implementation planned:
  * Implementation of Python's `watchdog` library to hook into OS filesystem events.
  * Baseline database tracking SHA-256 hashes of monitored files.
  * Real-time alerting: detects file creation, modification, and deletion.
  * Windows desktop push notifications and dashboard audit logging.

--- WEEK 7: FULL GUI INTEGRATION & HARDENING -----------------------------------
- What it does:
  * Unifies all 4 modules (Encrypt, Verify, Monitor, Shred) into a single cohesive 
    desktop dashboard.
- Technical implementation planned:
  * One-click lifecycle pipeline: Encrypt file -> Generate hash -> Shred original 
    -> Register in Monitor.
  * Live monitoring status tab and audit log exporter.
  * End-to-end user testing across multiple file types (PDF, images, text, binaries).

--- WEEK 8: FINAL REPORT, DOCUMENTATION & DEMO PREPARATION --------------------
- Deliverables:
  * Final project technical documentation and security architecture breakdown.
  * Live presentation demo script showing simulated attack/tamper detection.
================================================================================
