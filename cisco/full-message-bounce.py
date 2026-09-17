#!/usr/bin/env -S python3

import os
import subprocess
import tempfile
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from smtplib import SMTP


def encrypt_smime_der(msg, name: str = "encrypted.p7m") -> bytes:
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".eml") as temp_msg:
        temp_msg.write(msg.as_string())
        temp_msg_path = temp_msg.name

    encrypted_path = temp_msg_path + ".p7m"

    cmd = [
        "openssl",
        "smime",
        "-encrypt",
        "-in",
        temp_msg_path,
        "-out",
        encrypted_path,
        "-outform",
        "DER",
        "-binary",
        "smime/test-server-cert.crt",
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        with open(encrypted_path, "rb") as f:
            der_bytes = f.read()
            part = MIMEApplication(der_bytes, "pkcs7-mime", name=name)
            part.replace_header("Content-Type", f'application/pkcs7-mime; name="{name}"; smime-type=enveloped-data')
            part.replace_header("Content-Transfer-Encoding", "base64")
            part["Content-Disposition"] = f'attachment; filename="{name}"'
            return part
    finally:
        for p in (temp_msg_path, encrypted_path):
            try:
                os.unlink(p)
            except OSError:
                pass


msg = encrypt_smime_der(MIMEText('Hello, world!'))
msg['Subject'] = 'Test Email'
msg['From'] = 'test@external.test'
msg['To'] = 'smime@internal.test'

server = SMTP('10.0.2.15', 25)
server.send_message(msg)
server.quit()

print('Email sent successfully')
