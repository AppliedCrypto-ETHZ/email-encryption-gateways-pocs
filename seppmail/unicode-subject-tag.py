#!/usr/bin/env python3

from smtplib import SMTP
from email.message import EmailMessage


def main():
    email_msg = EmailMessage()
    email_msg.set_content("defs not secure")
    email_msg["Subject"] = f"insecure test message [s\u0435cur\u0435]"
    email_msg["From"] = "fake-user1@single.test"
    email_msg["To"] = "user1@single.test"
    email_msg["Date"] = "Today"

    with SMTP("192.168.56.101") as smtp:
        smtp.ehlo_or_helo_if_needed()
        smtp.send_message(email_msg)
        smtp.quit()


if __name__ == "__main__":
    main()
