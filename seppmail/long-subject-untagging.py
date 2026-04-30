#!/usr/bin/env python3

import os
import smtplib
import subprocess
import tempfile
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.message import MIMEMessage
from email.mime.text import MIMEText


def encrypt_email():
    email_content = "See, no tags. Just like it should be from an internal user."
    plain_part = MIMEText(email_content, 'plain')

    # Write the message to a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.eml') as temp_msg:
        temp_msg.write(plain_part.as_string())
        temp_msg_path = temp_msg.name

    encrypted_path = temp_msg_path + '.enc'
    openssl_encrypt_cmd = [
        'openssl', 'smime', '-encrypt',
        '-in', temp_msg_path,
        '-out', encrypted_path,
        '-outform', 'DER',
        '-binary',
        "Single_S_MIME_User_1.crt"
    ]

    subprocess.run(openssl_encrypt_cmd, check=True, capture_output=True)

    with open(encrypted_path, 'rb') as f:
        res = f.read()

    for temp_file in [temp_msg_path, encrypted_path]:
        try:
            os.unlink(temp_file)
        except:
            pass
    return res


def main():
    client = smtplib.SMTP("192.168.56.101")
    print(client.ehlo_or_helo_if_needed())
    encrypted = encrypt_email()
    encrypted_msg = MIMEApplication(encrypted, 'pkcs7-mime', name='smime.p7m')
    encrypted_msg['From'] = "user1@single.test"
    encrypted_msg['To'] = "smime1@single.test"
    encrypted_msg['Subject'] = "I'm definitely User1. Trust me." + " "*800 + "pad"
    encrypted_msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")

    outer_msg = MIMEMessage(encrypted_msg)
    outer_msg['From'] = "pt@tmp.test"
    outer_msg['To'] = "smime1@single.test"
    outer_msg['Subject'] = "Outer Message - Will be bounced anyway"

    print(client.sendmail("pt@tmp.test", ["smime1@single.test"], outer_msg.as_string()))
    print(client.quit())


if __name__ == "__main__":
    main()
