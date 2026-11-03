<img width="682" height="558" alt="{F05E0861-D110-476F-8160-48937FA67494}" src="https://github.com/user-attachments/assets/be9a3d90-1f2d-4809-a7ce-56e00805d9a5" 
  
  /># Secure File Lifecycle Manager - File Encryptor
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
<img width="682" height="558" alt="{F05E0861-D110-476F-8160-48937FA67494}" src="https://github.com/user-attachments/assets/5be3d3bc-0963-45ec-9d16-63765465a8a2" />

