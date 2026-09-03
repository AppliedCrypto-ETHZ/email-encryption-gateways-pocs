#!/usr/bin/env -S uv run --with pgpy
from smtplib import SMTP
from email.mime.text import MIMEText
from pgpy import PGPMessage, PGPKey

msg = PGPMessage.new(b"Your secret code is: correct-horse-battery-staple")
pk, _ = PGPKey.from_file("pgp1@single.test.asc")
pgpmsg = pk.encrypt(msg)

msg = MIMEText(str(pgpmsg))
msg["Subject"] = "foo"
msg["From"] = "pt@tmp.test"
msg["To"] = "pgp1@single.test"

with SMTP("192.168.56.101") as smtp:
    smtp.ehlo_or_helo_if_needed()
    smtp.send_message(msg)
    smtp.quit()
