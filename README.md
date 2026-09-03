# Artifacts

This repository contains proof-of-concept artifacts for _Delegating Email Encryption to Gateways: Why Johnny Should Not_. It includes only PoCs for issues where patches have been released.


## SEPPmail

| File | What it is | How to run/use |
|------|------------|----------------|
| `mixed-plaintext-and-encrypted-content.py` | Mixed plaintext/encrypted-content PoC. | Install `pgpy`, adjust the hard-coded SMTP host, email addresses, and key path if needed. Set up an http server that listens for the exfiltrated secrets and point ATTACKER_URL at the server. Then run `python3 mixed-plaintext-and-encrypted-content.py`. |
| `mime-boundary-injection.py` | MIME boundary-injection PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and public-key path if needed. Set up an http server that listens for the exfiltrated secrets and point ATTACKER_URL at the server. Then run `./mime-boundary-injection.py`. |
| `unicode-subject-tag.py` | Unicode subject-tag PoC. | Adjust the hard-coded SMTP host and email addresses if needed, then run `python3 unicode-subject-tag.py`. |
| `bounded-subject-tag-sanitization.txt` | Subject-tag sanitization test string. | Use the text as a message subject or fixture input. |
| `long-subject-untagging.py` | Long-subject S/MIME untagging PoC. | Install OpenSSL, adjust the hard-coded SMTP host, email addresses, and certificate path if needed, then run `python3 long-subject-untagging.py`. |
| `efail-direct-pgp.py` | EFAIL PGP direct-exfiltration PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and public-key path if needed. Set up an http server that listens for the exfiltrated secrets and point ATTACKER_URL at the server. Then run `./efail-direct-pgp.py`. |
| `efail-gadget-smime.py` | EFAIL S/MIME gadget PoC. | Install `uv` and the OpenSSL cli, adjust the hard-coded SMTP host, email addresses, and certificate path if needed. Set up an http server that listens for the exfiltrated secrets and point the exfiltration gadget at the server. Be careful to maintain block alignment. Then run `./efail-gadget-smime.py`. |
| `partial-signature.py` | Partial-signature PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and key path if needed, then run `./partial-signature.py`. |
| `bounce-padding-oracle.py` | CBC padding-oracle PoC. | Install `uv` and the OpenSSL cli. Adjust the hard-coded SMTP host, email addresses, and certificate path if needed, and set up `authbind` to allow receiving the generated DSNs. Then run `./bounce-padding-oracle.py`. |
| `header-decryption-oracle.py` | Header decryption-oracle PoC. | Install `uv` and the OpenSSL cli. Adjust the hard-coded SMTP host, email addresses, and certificate path if needed, and set up `authbind` to allow receiving the generated DSNs. Then run `./header-decryption-oracle.py`. |
| `full-message-bounce.py` | Full-message-bounce PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and key path if needed, then run `./full-message-bounce.py`. |


## Ciphermail

| File | What it is | How to run/use |
|------|------------|----------------|
| `efail-direct-pgp.py` | EFAIL PGP direct-exfiltration PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and key path if needed. Set up an http server that listens for the exfiltrated secrets and point ATTACKER_URL at the server. Then run `./efail-direct-pgp.py`. |
| `efail-gadget-pgp.py` | EFAIL PGP gadget PoC. | Install `uv` and the `gpg` cli, adjust the hard-coded SMTP host, email addresses, and key path if needed. Set up an http server that listens for the exfiltrated secrets and point the exfiltration gadget at the server. Be careful to maintain block alignment. Then run `./efail-gadget-pgp.py`. |
| `efail-gadget-smime.py` | EFAIL S/MIME gadget PoC. | Install `uv` and the OpenSSL cli, adjust the hard-coded SMTP host, email addresses, and certificate path if needed. Set up an http server that listens for the exfiltrated secrets and point the exfiltration gadget at the server. Be careful to maintain block alignment. Then run `./efail-gadget-smime.py`. |
| `mixed-plaintext-and-encrypted-content.py` | Mixed plaintext/encrypted-content PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and key path if needed, then run `./mixed-plaintext-and-encrypted-content.py`. |
| `partial-signature.py` | Partial-signature PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and key path if needed, then run `./partial-signature.py`. |
| `mime-boundary-injection.py` | MIME boundary-injection PoC. | Install `uv`, adjust the hard-coded SMTP host, email addresses, and key path if needed. Set up an http server that listens for the exfiltrated secrets and point ATTACKER_URL at the server. Then run `./mime-boundary-injection.py`. |
| `bounce-padding-oracle.py` | CBC padding-oracle PoC. | Install `uv` and the OpenSSL cli. Adjust the hard-coded SMTP host, email addresses, and certificate path if needed, and set up `authbind` to allow receiving the generated DSNs. Then run `./bounce-padding-oracle.py`. |
| `header-decryption-oracle.py` | Header decryption-oracle PoC. | Install `uv` and the OpenSSL cli. Adjust the hard-coded SMTP host, email addresses, and certificate path if needed, and set up `authbind` to allow receiving the generated DSNs. Then run `./header-decryption-oracle.py`. |
| `full-message-bounce.py` | Full-message-bounce PoC. | Install the OpenSSL cli, adjust the SMTP host and certificate path (CLI flags) if needed, then run `./full-message-bounce.py`. |
| `subject-tag.py` | Unicode subject-tag and bounded subject-tag sanitization PoC. | Adjust the hard-coded SMTP host and email addresses if needed, then run `./subject-tag.py` (add `--unicode` for the Unicode variant). |
| `long-subject-untagging.py` | Long-subject S/MIME untagging PoC. | Install OpenSSL, adjust the hard-coded SMTP host, email addresses, and certificate path if needed, then run `./long-subject-untagging.py`. |


## Proton Mail Bridge

`boundary-injection.py` is a [mitmproxy](https://mitmproxy.org/) addon that rewrites Bridge's HTTPS API responses as if a malicious Proton server were splicing attacker HTML around a genuine ciphertext. Bridge must trust mitmproxy's CA and send its HTTPS through the proxy:

1. Install deps: `pip install -r requirements.txt`.
2. Start mitmproxy with the addon: `mitmdump -s boundary-injection.py` (listens on `:8080` by default). The first run writes a CA under `~/.mitmproxy/`.
3. Trust that CA in the system store (Linux / Debian-style):

```sh
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

4. Start Bridge through the proxy:

```sh
HTTPS_PROXY=http://127.0.0.1:8080 bridge --cli
```

5. Adjust `EXFIL_URL` in the script if needed, then fetch/open a message through Bridge.

| File | What it is | How to run/use |
|------|------------|----------------|
| `boundary-injection.py` | mitmproxy addon that implements the MIME boundary-injection. | Run with `mitmdump -s boundary-injection.py` after the setup above. |


## MUA

| File | What it is | How to run/use |
|------|------------|----------------|
| `03-pgp-efail-direct-multipart-splice.eml` | PGP EFAIL direct-exfiltration fixture. | Adjust the hard-coded img host in the fixture if needed, then open in the target MUA; look for an HTTP request carrying the spliced secret (you can use `request_logger_server.py` to monitor). |
| `06-user-signalling-unicode-homoglyph.eml` | Unicode homoglyph subject-tag fixture (Cyrillic lookalike forging a `[decrypted]` tag). | Open in the target MUA; check whether the forged tag is distinguishable from a real warning tag. |
| `07-user-signalling-unicode-rtl-override.eml` | Unicode RTL-override subject-tag fixture (`U+202E` / `U+202C` forging a `[decrypted]` lookalike). | Open in the target MUA; check whether RTL-overrides are neutralized or the forged tag looks legitimate. |
| `08-user-signalling-unicode-zero-width.eml` | Unicode zero-width subject-tag fixture (`U+200B` inside a lookalike `[decrypted]` tag). | Open in the target MUA; check whether the zero-width character is visible or the forged tag looks legitimate. |
| `09-user-signalling-tag-hiding-spaces.eml` | Subject-tag hiding via a long run of spaces before `[mixed content]`. | Open in the target MUA; check whether the warning tag is visible in the subject. |
| `10-user-signalling-tag-hiding-tabs.eml` | Subject-tag hiding via a long run of tabs before `[mixed content]`. | Open in the target MUA; check whether the warning tag is visible in the subject. |
| `request_logger_server.py` | HTTP request logger for client probe / exfil requests. | Run `python3 request_logger_server.py` (defaults to `0.0.0.0:8080`, appends JSON Lines to `requests.jsonl`). |

