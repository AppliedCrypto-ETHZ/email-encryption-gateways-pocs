#!/usr/bin/env -S python3

import argparse
import os
import smtplib
import subprocess
import tempfile
from email import policy
from email.generator import BytesGenerator
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def encrypt_smime_der(plaintext_message: str, cert_path: str) -> bytes:
    msg = MIMEText(plaintext_message, "plain", "utf-8")

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
        cert_path,
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        with open(encrypted_path, "rb") as f:
            return f.read()
    finally:
        for p in (temp_msg_path, encrypted_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def make_smime_part(der_bytes: bytes, name: str) -> MIMEApplication:
    part = MIMEApplication(der_bytes, "pkcs7-mime", name=name)
    part.replace_header("Content-Type", f'application/pkcs7-mime; name="{name}"; smime-type=enveloped-data')
    part.replace_header("Content-Transfer-Encoding", "base64")
    part["Content-Disposition"] = f'attachment; filename="{name}"'
    return part


def build_message(cert_path: str, sender: str, recipient: str, subject: str) -> MIMEMultipart:
    root = MIMEMultipart("mixed")
    root["From"] = sender
    root["To"] = recipient
    root["Subject"] = subject
    root["Date"] = "absolutely not a date"

    enc1 = encrypt_smime_der("S/MIME encrypted payload #1", cert_path)
    root.attach(make_smime_part(enc1, "smime.p7m"))

    return root


def write_eml(msg: MIMEMultipart, output_path: str) -> None:
    with open(output_path, "wb") as f:
        generator = BytesGenerator(f, policy=policy.SMTP)
        generator.flatten(msg)


def send_message(msg: MIMEMultipart, smtp_host: str, smtp_port: int) -> None:
    with smtplib.SMTP(smtp_host, smtp_port) as smtp:
        smtp.send_message(msg)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a multipart email with multiple S/MIME encrypted parts."
    )
    parser.add_argument("--cert", default="../smime1-at-internal.test.pem", help="Recipient cert PEM path.")
    parser.add_argument("--from", dest="sender", default="temp@external.test", help="From address.")
    parser.add_argument("--to", dest="recipient", default="smime1@internal.test", help="To address.")
    parser.add_argument("--subject", default="Multipart with multiple S/MIME encrypted parts", help="Subject.")
    parser.add_argument("--output", default="multi-smime-parts.eml", help="Output .eml path.")
    parser.add_argument("--dry-run", action="store_true", help="Only build the message, do not send it via SMTP.")
    parser.add_argument("--smtp-host", default="10.0.2.2", help="SMTP host.")
    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP port.")
    args = parser.parse_args()

    msg = build_message(args.cert, args.sender, args.recipient, args.subject)
    write_eml(msg, args.output)
    print(f"Wrote {args.output}")

    if not args.dry_run:
        send_message(msg, args.smtp_host, args.smtp_port)
        print(f"Sent via SMTP {args.smtp_host}:{args.smtp_port}")


if __name__ == "__main__":
    main()
