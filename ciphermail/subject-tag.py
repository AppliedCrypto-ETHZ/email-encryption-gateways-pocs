#!/usr/bin/env python3
"""Send a plain text email via SMTP."""

import smtplib
import argparse
from email.mime.text import MIMEText

class EmailSender:
    def send_email(self, smtp_server, from_address, recipient_email, email_content, subject):
        """Send a plain email via SMTP."""
        print(f"Sending email to {recipient_email}...")

        # Create the email message
        msg = MIMEText(email_content, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = from_address
        msg['To'] = recipient_email

        # Connect to SMTP server
        try:
            server = smtplib.SMTP(smtp_server)

            # Send email
            server.send_message(msg)
            server.quit()

            print("Email sent successfully!")
            return True

        except Exception as e:
            print(f"Error sending email: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Plain SMTP email sender')
    parser.add_argument('--unicode', action='store_true',
                       help='Send Unicode subject')

    args = parser.parse_args()

    if args.unicode:
        subject = "[signеd] clearly safe email"
    else:
        subject = "[sig[signed]ned] clearly safe email"

    # Initialize sender
    sender = EmailSender()

    # Send email
    success = sender.send_email(
        smtp_server="10.0.2.2",
        from_address="sender@external.test",
        recipient_email="recipient@internal.test",
        email_content="This is a test email.",
        subject=subject,
    )

    if success:
        print("Script completed successfully!")
    else:
        print("Script failed!")
        exit(1)


if __name__ == "__main__":
    main()
