#!/usr/bin/env python3
"""
SecureClientVault

A small command-line tool to encrypt and decrypt client CSV files
using symmetric encryption, with a basic password policy and logging.

Usage:
    python3 secure_vault.py encrypt clients.csv encrypted_clients.bin
    python3 secure_vault.py decrypt encrypted_clients.bin decrypted_clients.csv
"""

import argparse
import getpass
import logging
import os
import sys
from base64 import urlsafe_b64encode
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# ---------- CONFIG ---------- #

SALT_SIZE = 16              # bytes
KDF_ITERATIONS = 390_000    # PBKDF2 iterations
LOG_FILE = "secure_vault.log"

# ---------- LOGGING ---------- #

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ---------- PASSWORD HELPERS ---------- #

def get_password(confirm: bool = False) -> str:
    """
    Prompt the user for a password (no echo).
    If confirm=True, ask twice and verify they match.
    """
    while True:
        pwd = getpass.getpass("Enter password: ")
        if confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                print("Passwords do not match. Please try again.\n")
                continue
        return pwd


def password_is_strong(password: str) -> Tuple[bool, str]:
    """
    Simple password policy:
    - at least 12 characters
    - at least one lowercase, uppercase, digit, and symbol
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if not (has_lower and has_upper and has_digit and has_symbol):
        return False, (
            "Password must include at least one lowercase letter, "
            "one uppercase letter, one digit, and one symbol."
        )

    return True, ""

# ---------- KEY DERIVATION ---------- #

def derive_fernet(password: str, salt: bytes) -> Fernet:
    """
    Derive a Fernet key from a password and salt using PBKDF2-HMAC (SHA-256).
    """
    password_bytes = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,               # 32-byte key
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password_bytes)
    fernet_key = urlsafe_b64encode(key)
    return Fernet(fernet_key)

# ---------- ENCRYPT / DECRYPT ---------- #

def encrypt_file(input_path: str, output_path: str) -> None:
    """
    Encrypt the contents of input_path and write them to output_path.
    Output format: [salt][ciphertext]
    """
    if not os.path.exists(input_path):
        print(f"Input file '{input_path}' does not exist.")
        return

    password = get_password(confirm=True)
    ok, msg = password_is_strong(password)
    if not ok:
        print("Weak password:", msg)
        return

    salt = os.urandom(SALT_SIZE)
    f = derive_fernet(password, salt)

    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()

    ciphertext = f.encrypt(plaintext)

    with open(output_path, "wb") as f_out:
        f_out.write(salt + ciphertext)

    logging.info(f"ENCRYPT: {input_path} -> {output_path} SUCCESS")
    print(f"Encrypted '{input_path}' to '{output_path}'.")


def decrypt_file(input_path: str, output_path: str) -> None:
    """
    Decrypt the contents of input_path and write them to output_path.
    Expects input format: [salt][ciphertext]
    """
    if not os.path.exists(input_path):
        print(f"Input file '{input_path}' does not exist.")
        return

    password = get_password(confirm=False)

    with open(input_path, "rb") as f_in:
        data = f_in.read()

    if len(data) < SALT_SIZE:
        print("Encrypted file is too short to contain salt.")
        return

    salt = data[:SALT_SIZE]
    ciphertext = data[SALT_SIZE:]
    f = derive_fernet(password, salt)

    try:
        plaintext = f.decrypt(ciphertext)
    except Exception as e:
        logging.warning(f"DECRYPT FAILED: {input_path} -> {output_path} ({e})")
        print("Decryption failed. Incorrect password or corrupted file.")
        return

    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)

    logging.info(f"DECRYPT: {input_path} -> {output_path} SUCCESS")
    print(f"Decrypted '{input_path}' to '{output_path}'.")

# ---------- CLI ---------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SecureClientVault: encrypt and decrypt client files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("input", help="Path to input file (e.g., clients.csv)")
    encrypt_parser.add_argument("output", help="Path to encrypted output file")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("input", help="Path to encrypted input file")
    decrypt_parser.add_argument("output", help="Path to decrypted output file")

    return parser


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "encrypt":
        encrypt_file(args.input, args.output)
    elif args.command == "decrypt":
        decrypt_file(args.input, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
