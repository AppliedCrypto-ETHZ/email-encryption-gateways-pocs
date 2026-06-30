#!/usr/bin/env -S authbind --depth 2 uv run --with cryptography --with aiosmtpd --with asn1crypto python

import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from aiosmtpd.controller import Controller
import asyncio
from base64 import b64decode as b64d

class SimpleMailServer:
    def __init__(self):
        self.controller = None
        self.done = False
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return '250 OK'
    
    async def handle_DATA(self, server, session, envelope):
        lines = envelope.content.decode("utf-8", "replace").split("\r\n")
        head = [l for l in lines if l.startswith("Content-Type: ")][0]
        print("THE SECRET IS:", head.split(": ")[1])
        self.done = True
        return '250 Message accepted for delivery'
    
    def start(self, host='10.0.2.1', port=25):
        self.controller = Controller(self, hostname=host, port=port)
        self.controller.start()
        print(f"SMTP Server listening on {host}:{port}...")
        return self.controller
    
    def stop(self):
        if self.controller:
            self.controller.stop()


class SMIMESigner:
    def __init__(self, key_size=2048):
        self.key_size = key_size

    def encrypt_email(self):
        from_address = "temp@external.test"
        to_address = "smime1@internal.test"
        email_content = "Your secret code: T0p_S3cret\n\nDo not share this code with anyone."
        subject = "Secret Code"

        print("Signing email with S/MIME...")

        # Create the email message
        msg = MIMEText(email_content, 'plain')

        # Create proper S/MIME signature using OpenSSL
        import subprocess
        import tempfile

        # Write the message to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.eml') as temp_msg:
            temp_msg.write(msg.as_string())
            temp_msg_path = temp_msg.name
            temp_msg.flush()
            os.fsync(temp_msg.fileno())
            
            # Encrypt the signed message
            encrypted_path = temp_msg_path + '.enc'
            openssl_encrypt_cmd = [
                'openssl', 'smime', '-encrypt',
                '-in', temp_msg_path,
                '-out', encrypted_path,
                '-outform', 'DER',
                '-binary',
                "../smime1-at-internal.test.pem"
            ]

            subprocess.run(openssl_encrypt_cmd, check=True, capture_output=True)

            # Read the encrypted data
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
                os.unlink(encrypted_path)
                return encrypted_data


    def make_mail(self):
        encrypted_data = self.encrypt_email()
        # Parse the SignedData structure using asn1crypto
        from asn1crypto import cms

        # Also parse the EnvelopedData structure
        env_content_info = cms.ContentInfo.load(encrypted_data)
        assert env_content_info['content_type'].dotted == "1.2.840.113549.1.7.3"
        print("Successfully parsed EnvelopedData:")
        enveloped_data = env_content_info['content']
        encrypted_content_info = enveloped_data['encrypted_content_info']
        encrypted_content = encrypted_content_info['encrypted_content'].contents
        
        content_encryption_algorithm = encrypted_content_info['content_encryption_algorithm']
        algorithm = content_encryption_algorithm['algorithm'].dotted
        
        print(f"Content encryption algorithm: {algorithm}")
        print(f"Encrypted content length: {len(encrypted_content)} bytes")
        
        assert algorithm in ["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42"] # AES CBC (according to some LLM)

        iv = encrypted_content[80:96]
        def xor(a, b):
            assert len(a) == len(b) == 16
            return bytes(i ^ j for i, j in zip(a, b))
        iv = xor(iv, xor(b'Your secret code', b'Content-Type    '))
        
        # Create a new ContentInfo with modified data
        from asn1crypto import core
        
        # Create new algorithm identifier with modified IV
        new_algorithm = cms.EncryptionAlgorithm({
            'algorithm': content_encryption_algorithm['algorithm'],
            'parameters': core.OctetString(iv)
        })
        
        # Create new encrypted content with modifications
        modified_encrypted_content = encrypted_content[96:128] + encrypted_content[-32:]
        print(f"Length check: orig={len(encrypted_content)}, mod={len(modified_encrypted_content)}")
        
        # Create new EncryptedContentInfo
        new_encrypted_content_info = cms.EncryptedContentInfo({
            'content_type': encrypted_content_info['content_type'],
            'content_encryption_algorithm': new_algorithm,
            'encrypted_content': core.OctetString(modified_encrypted_content)
        })
        
        # Create new EnvelopedData
        new_enveloped_data = cms.EnvelopedData({
            'version': enveloped_data['version'],
            'recipient_infos': enveloped_data['recipient_infos'],
            'encrypted_content_info': new_encrypted_content_info
        })
        
        # Create new ContentInfo
        new_content_info = cms.ContentInfo({
            'content_type': env_content_info['content_type'],
            'content': new_enveloped_data
        })
        
        # Dump the new structure
        encrypted_data = new_content_info.dump()

        # Create final encrypted message
        encrypted_msg = MIMEApplication(encrypted_data, 'pkcs7-mime', name='smime.p7m')
        encrypted_msg['From'] = "temp@external.test"
        encrypted_msg['To'] = "smime1@internal.test"
        encrypted_msg['Subject'] = "Secret Code"

        return encrypted_msg

    def send_mail(self):
        """Send a signed email via plain SMTP"""
        print(f"Sending email...")

        # Create and sign the email
        msg = self.make_mail()

        # Connect to SMTP server
        try:
            server = smtplib.SMTP("10.0.2.2")

            # Send email
            server.send_message(msg)
            server.quit()

            print("Email sent successfully!")
            return True

        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error sending email: {e}")
            return False


async def main():

    server = SimpleMailServer()
    server.start()

    # Initialize signer
    signer = SMIMESigner()

    # Send signed email
    success = signer.send_mail()
    if not success:
        print("Failed to send email")
        exit(1)
    print()

    while not server.done:
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
