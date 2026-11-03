# Secure File Lifecycle Manager - File Encryptor

College project - encrypt, verify and securely shred files.

## Features
- AES-style XOR encryption with password (`crypto_engine.py`)
- Integrity verification with SHA-256 (`verify`)
- Secure shredding - anti-forensics overwrite (`shred_engine.py`)
- CLI (`cli.py`) + GUI (`gui.py`)
- Tests: `test_crypto.py`, `test_shred.py`

## Usage
```bash  
pip install -r requirements.txt  
python cli.py encrypt secret.txt  
python cli.py decrypt secret.txt.enc  
python cli.py verify secret.txt.enc  
python cli.py shred secret.txt  
