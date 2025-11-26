# SecureClientVault

A small command-line tool to **encrypt and decrypt client CSV files** using symmetric encryption.  
This project grew out of a real-world problem: small businesses often keep their client lists in plain text, which makes it easy for competitors or attackers to steal years of work with a single file.

## Features

- Encrypts any file (e.g., `clients.csv`) into a binary blob using **symmetric cryptography (Fernet/AES)**.
- Decrypts the encrypted file back to its original form when the correct password is provided.
- Derives encryption keys from a user password using **PBKDF2-HMAC with SHA-256 and a random salt**.
- Enforces a simple **password-strength policy**:
  - minimum length: 12 characters  
  - requires lowercase, uppercase, digit, and symbol
- Logs encryption and decryption attempts (success and failure) to `secure_vault.log`.

## Installation

```bash
pip install cryptography
