#!/usr/bin/env -S uv run --with pgpy
"""
Send an inline PGP signed-and-encrypted message to the owner of ../pgp1-intern-pub.asc.

Signs with ../pgp1-extern-sec.asc (copy or symlink from the paths printed by
Encrypts to ../pgp1-intern-pub.asc.

Edit PLAINTEXT / SUBJECT below if needed, then run:
  ./inline-pgp.py
"""

import re
import smtplib
from email.message import EmailMessage
from pathlib import Path

import pgpy

# --- config (no CLI) ---
SMTP_HOST = "10.0.2.2"
SMTP_PORT = 25
SENDER = "plain@external.test"
SUBJECT = "Inline PGP test"
PLAINTEXT = "Hello from pgpy"

SCRIPT_DIR = Path(__file__).resolve().parent
PUBKEY_PATH = (SCRIPT_DIR / "../pgp1-intern-pub.asc").resolve()

def load_public_key(key_path: Path) -> pgpy.PGPKey:
    key_data = key_path.read_text(encoding="utf-8")
    key, _ = pgpy.PGPKey.from_blob(key_data)

    if key.is_public is False:
        raise ValueError(f"Expected a public key at {key_path}, got private key material")

    return key


def load_secret_key(key_path: Path) -> pgpy.PGPKey:
    key_data = key_path.read_text(encoding="utf-8")
    key, _ = pgpy.PGPKey.from_blob(key_data)

    if key.is_public:
        raise ValueError(f"Expected a secret key at {key_path}, got public key material")
    if not key.is_unlocked:
        raise ValueError(
            f"Secret key at {key_path} is passphrase-locked; use an unencrypted key or extend the script to unlock."
        )

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


def encrypt_inline(
    recipient_pubkey: pgpy.PGPKey,
    plaintext: str,
) -> str:
    """Sign plaintext with ``signing_key``, then encrypt the signed literal to ``recipient_pubkey``."""
    pgp_message = pgpy.PGPMessage.new(plaintext, cleartext=False)
    encrypted = recipient_pubkey.encrypt(pgp_message)
    return str(encrypted)

def build_email(sender: str, recipient: str, subject: str, encrypted_body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(encrypted_body)
    del msg["Content-Type"]
    msg["Content-Type"] = "text/plain; charset=utf-8"
    print(msg.as_string())
    return msg


def send_mail(host: str, port: int, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.send_message(msg)


def main() -> None:
    public_key = load_public_key(PUBKEY_PATH)
    recipient = recipient_email_from_key(public_key)

    encrypted_body = encrypt_inline(public_key, PLAINTEXT)
    payload = encrypt_inline(public_key, "fake1") + "\n" + encrypted_body + "\n" + encrypt_inline(public_key, "fake2")
    email_message = build_email(SENDER, recipient, SUBJECT, payload)
    send_mail(SMTP_HOST, SMTP_PORT, email_message)

    print(
        f"Signed and encrypted inline PGP message sent from {SENDER} to {recipient} "
        f"(key owner) via {SMTP_HOST}:{SMTP_PORT}"
    )


if __name__ == "__main__":
    main()
