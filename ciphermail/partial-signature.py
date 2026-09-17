#!/usr/bin/env -S uv run --with pgpy
"""
Send a multipart/mixed message with:
- one attached (non-detached) signed OpenPGP blob (trigger part)
- one data attachment + one detached OpenPGP signature attachment

The trigger part helps ensure CipherMail enters the PGP/INLINE post-validation
path. The detached pair matches the filename-based logic in
PGPRecursiveValidatingMIMEHandler (payload.txt + payload.txt.pgp).
"""

import smtplib
from email.message import EmailMessage
from pathlib import Path
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pgpy

# --- config (no CLI) ---
SMTP_HOST = "10.0.2.2"
SMTP_PORT = 25
SENDER = "pgp1@external.test"
RECIPIENT = "pgp1@internal.test"
SUBJECT = "PGP detached attachment signature test"
TRIGGER_FILENAME = "trigger.txt.asc"
ATTACHMENT_FILENAME = "payload.txt"
SIGNED_TEXT = "Hello from pgpy detached signature demo.\n"

SCRIPT_DIR = Path(__file__).resolve().parent
SECKEY_PATH = (SCRIPT_DIR / "../pgp1-at-external.test-sec.asc").resolve()


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


def attached_signed_message_ascii(signing_key: pgpy.PGPKey, plaintext: str) -> bytes:
    """
    Create an armored signed OpenPGP message (non-detached signature packet included).
    """
    pgp_message = pgpy.PGPMessage.new(plaintext, cleartext=False)
    signature = signing_key.sign(pgp_message)
    pgp_message |= signature
    return str(pgp_message).encode("utf-8")


def detach_signature_from_attached_signature(attached_signed_ascii: bytes) -> bytes:
    """
    Parse an attached-signed OpenPGP message and return the detached signature armor.
    """
    parsed = pgpy.PGPMessage.from_blob(attached_signed_ascii.decode("utf-8"))
    message = parsed[0] if isinstance(parsed, tuple) else parsed
    signatures = list(message.signatures)
    if not signatures:
        raise ValueError("Attached signed message did not contain a signature.")
    return str(signatures[0]).encode("utf-8")


def build_email(
    sender: str,
    recipient: str,
    subject: str,
    trigger_signature_bytes: bytes,
    payload_bytes: bytes,
) -> EmailMessage:
    detached_signature_bytes = detach_signature_from_attached_signature(trigger_signature_bytes)

    msg = MIMEMultipart("related")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    msg.attach(MIMEText("fake message", "plain", "utf-8"))

    trigger_part = MIMEApplication(
        trigger_signature_bytes,
        "octet-stream",
        Name=TRIGGER_FILENAME,
    )
    trigger_part.add_header("Content-Disposition", "inline", filename=TRIGGER_FILENAME)
    msg.attach(trigger_part)

    signed_part = MIMEApplication(payload_bytes, "octet-stream")
    signed_part.add_header("Content-Disposition", "inline", filename=ATTACHMENT_FILENAME)
    msg.attach(signed_part)

    signature_filename = f"{ATTACHMENT_FILENAME}.pgp"
    signature_part = MIMEApplication(
        detached_signature_bytes,
        "octet-stream",
        Name=signature_filename,
    )
    signature_part.add_header("Content-Disposition", "inline", filename=signature_filename)
    msg.attach(signature_part)
    msg.attach(signature_part)

    return msg


def send_mail(host: str, port: int, msg: EmailMessage) -> None:
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.send_message(msg)


def main() -> None:
    signing_key = load_secret_key(SECKEY_PATH)
    payload_bytes = SIGNED_TEXT.encode("utf-8")

    # Sign once (non-detached), then derive detached signature from it.
    trigger_signature_bytes = attached_signed_message_ascii(signing_key, SIGNED_TEXT)

    message = build_email(
        SENDER,
        RECIPIENT,
        SUBJECT,
        trigger_signature_bytes,
        payload_bytes,
    )
    send_mail(SMTP_HOST, SMTP_PORT, message)

    print(f"Detached-signature mail sent from {SENDER} to {RECIPIENT} via {SMTP_HOST}:{SMTP_PORT}")


if __name__ == "__main__":
    main()
