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
        lines = envelope.content.decode().split("\r\n")
        head = [l for l in lines if l.startswith("dummy: ")][0]
        print("THE SECRET IS:", b64d(head.split(": ")[1]).decode())
        self.done = True
        return '250 Message accepted for delivery'
    
    def start(self, host='192.168.56.1', port=25):
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
        self.private_key = None
        self.certificate = None
        self.ca_certificate = None

    def load_certificate_and_key(self):
        cert_file="certificate.pem"
        key_file="private_key.pem"
        print(f"Loading certificate from {cert_file}...")
        with open(cert_file, "rb") as f:
            cert_data = f.read()
            self.certificate = load_pem_x509_certificate(cert_data)

        print(f"Loading private key from {key_file}...")
        with open(key_file, "rb") as f:
            key_data = f.read()
            self.private_key = load_pem_private_key(key_data, password=None)

    def load_ca_certificate_and_key(self):
        ca_cert_file="ca_certificate.pem"
        print(f"Loading CA certificate from {ca_cert_file}...")
        with open(ca_cert_file, "rb") as f:
            cert_data = f.read()
            self.ca_certificate = load_pem_x509_certificate(cert_data)

    def encrypt_email(self):
        from_address = "temp@tmp.test"
        to_address = "smime1@single.test"
        email_content = "T0p_S3cret"
        subject = "Secret Code"
        if not self.certificate or not self.private_key:
            raise ValueError("Certificate and private key must be loaded first")

        print("Signing email with S/MIME...")

        # Create the email message
        msg = MIMEText(email_content, 'plain', 'utf-8')
        msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        msg['Subject'] = subject
        msg['From'] = from_address
        msg['To'] = to_address

        # Create signed email with proper S/MIME structure
        signed_msg = MIMEMultipart('signed', protocol='application/x-pkcs7-signature', micalg='sha-256')
        signed_msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        signed_msg['Subject'] = subject
        signed_msg['From'] = from_address
        signed_msg['To'] = to_address

        # Add the original message
        signed_msg.attach(msg)

        # Create proper S/MIME signature using OpenSSL
        import subprocess
        import tempfile

        # Write the message to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.eml') as temp_msg:
            temp_msg.write(msg.as_string())
            temp_msg_path = temp_msg.name

        # Write certificate and key to temporary files
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as temp_cert:
            temp_cert.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            temp_cert_path = temp_cert.name

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as temp_key:
            temp_key.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            temp_key_path = temp_key.name

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='_ca.pem') as temp_ca_cert:
            temp_ca_cert.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
            temp_ca_cert_path = temp_ca_cert.name

        # Create signature using OpenSSL
        signature_path = temp_msg_path + '.sig'
        temp_signed_path = None
        encrypted_path = None
        try:
            # Prepare OpenSSL command
            openssl_cmd = [
                'openssl', 'smime', '-sign',
                '-in', temp_msg_path,
                '-out', signature_path,
                '-signer', temp_cert_path,
                '-inkey', temp_key_path,
                '-outform', 'DER',
                '-certfile', temp_ca_cert_path,
            ]

            subprocess.run(openssl_cmd, check=True, capture_output=True)

            # Read the signature
            with open(signature_path, 'rb') as f:
                signature_data = f.read()

            # Add the signature
            signature_part = MIMEApplication(signature_data, 'pkcs7-signature', name='smime.p7s')
            signed_msg.attach(signature_part)

            # Now encrypt the signed message
            print("Encrypting the signed message...")
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='_signed.eml') as temp_signed:
                temp_signed.write(signed_msg.as_string())
                temp_signed_path = temp_signed.name
            
            # Encrypt the signed message
            encrypted_path = temp_signed_path + '.enc'
            openssl_encrypt_cmd = [
                'openssl', 'smime', '-encrypt',
                '-in', temp_signed_path,
                '-out', encrypted_path,
                '-outform', 'DER',
                '-binary',
                "Single_S_MIME_User_1.crt"
            ]

            subprocess.run(openssl_encrypt_cmd, check=True, capture_output=True)

            # Read the encrypted data
            with open(encrypted_path, 'rb') as f:
                return f.read()
        finally:
            temp_files = [temp_msg_path, temp_cert_path, temp_key_path, signature_path, encrypted_path, temp_ca_cert_path, temp_signed_path]
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass


    def make_mail(self):
        encrypted_data = self.encrypt_email()
        # Parse the EnvelopedData structure using asn1crypto
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
        
        iv = encrypted_content[464:480]
        def xor(a, b):
            assert len(a) == len(b) == 16
            return bytes(i ^ j for i, j in zip(a, b))
        iv = xor(iv, xor(b'.test\n\n\0\0\0\0\0\0\0\0\0', b'dummy: \0\0\0\0\0\0\0\0\0'))
        
        # Create a new ContentInfo with modified data
        from asn1crypto import core
        
        # Create new algorithm identifier with modified IV
        new_algorithm = cms.EncryptionAlgorithm({
            'algorithm': content_encryption_algorithm['algorithm'],
            'parameters': core.OctetString(iv)
        })
        
        # Create new encrypted content with modifications
        modified_encrypted_content = encrypted_content[480:512] + encrypted_content[-32:]
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
        encrypted_msg['From'] = "pt@tmp.test"
        encrypted_msg['To'] = "smime1@single.test"

        return encrypted_msg

    def send_mail(self):
        """Send a signed email via plain SMTP"""
        if not self.certificate or not self.private_key:
            raise ValueError("Certificate and private key must be loaded first")

        print(f"Sending email...")

        # Create and sign the email
        msg = self.make_mail()

        # Connect to SMTP server
        try:
            server = smtplib.SMTP("192.168.56.101")

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
    signer.load_ca_certificate_and_key()
    signer.load_certificate_and_key()

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
