#!/usr/bin/env -S uv run --with pgpy
from smtplib import SMTP
from email.message import EmailMessage
from email.utils import formatdate
from pgpy import PGPMessage, PGPKey

msg = PGPMessage.new(b"Absolutly do not do A under any circumstances!")
sk, _ = PGPKey.from_file("key.asc")

msg |= sk.sign(msg)
pgpmsg = msg

msg = EmailMessage()
msg.set_content("Just do A please.")
msg.add_related(str(pgpmsg))
msg["Subject"] = "Signed Message"
msg["From"] = "oldhash@tmp.test"
msg["To"] = "pgp1@single.test"
msg["Date"] = formatdate(localtime=True)

with SMTP("192.168.56.101") as smtp:
    smtp.ehlo_or_helo_if_needed()
    smtp.send_message(msg)
    smtp.quit()
