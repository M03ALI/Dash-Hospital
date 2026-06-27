#!/usr/bin/env python3
"""
Generate a salted PBKDF2 password hash for the Hospital Dashboard analyst login.

Usage:
    python make_hash.py "your-strong-password"

Copy the printed value and set it as HOSPITAL_ADMIN_PASSWORD_HASH:
  • Streamlit Community Cloud:  App → Settings → Secrets
  • Local / server:             export HOSPITAL_ADMIN_PASSWORD_HASH="...."

The plaintext password is never stored anywhere.
"""
import sys
import hashlib
import secrets

ITERS = 600_000


def make_password_hash(pw, iters=ITERS):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters).hex()
    return f"pbkdf2_sha256${iters}${salt.hex()}${digest}"


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1]:
        print('Usage: python make_hash.py "your-strong-password"')
        sys.exit(1)
    if len(sys.argv[1]) < 8:
        print("Warning: use at least 8 characters for a strong password.")
    print(make_password_hash(sys.argv[1]))
