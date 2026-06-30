# Artifacts

This repository contains proof-of-concept artifacts for _Delegating Email Encryption to Gateways: Why Johnny Should Not_. It includes only PoCs for issues where patches have been released.

## SEPPmail

| File | What it is | How to run/use |
|------|------------|----------------|
| `mixed-plaintext-and-encrypted-content.py` | Mixed plaintext/encrypted-content PoC. | Install `pgpy`, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `python3 mixed-plaintext-and-encrypted-content.py`. |
| `mime-boundary-injection.py` | MIME boundary-injection PoC. | Install `uv`, adjust the hard-coded SMTP host, addresses, and public-key path if needed, then run `./mime-boundary-injection.py`. |
| `unicode-subject-tag.py` | Unicode subject-tag PoC. | Adjust the hard-coded SMTP host and addresses if needed, then run `python3 unicode-subject-tag.py`. |
| `bounded-subject-tag-sanitization.txt` | Subject-tag sanitization test string. | Use the text as a message subject or fixture input. |
| `long-subject-untagging.py` | Long-subject S/MIME untagging PoC. | Install OpenSSL, adjust the hard-coded SMTP host, addresses, and certificate path if needed, then run `python3 long-subject-untagging.py`. |

## Ciphermail

| File | What it is | How to run/use |
|------|------------|----------------|
| `efail-direct-pgp.py` | EFAIL PGP direct-exfiltration PoC. | Install `uv`, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `./efail-direct-pgp.py`. |
| `efail-gadget-pgp.py` | EFAIL PGP gadget PoC. | Install `uv` and the `gpg` cli, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `./efail-gadget-pgp.py`. |
| `efail-gadget-smime.py` | EFAIL S/MIME gadget PoC. | Install `uv` and the OpenSSL cli, adjust the hard-coded SMTP host, addresses, and certificate path if needed, then run `./efail-gadget-smime.py`. |
| `mixed-plaintext-and-encrypted-content.py` | Mixed plaintext/encrypted-content PoC. | Install `uv`, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `./mixed-plaintext-and-encrypted-content.py`. |
| `partial-signature.py` | Partial-signature PoC. | Install `uv`, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `./partial-signature.py`. |
| `mime-boundary-injection.py` | MIME boundary-injection PoC. | Install `uv`, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `./mime-boundary-injection.py`. |
| `bounce-padding-oracle.py` | CBC padding-oracle PoC. | Install `uv` and the OpenSSL cli. Adjust the hard-coded SMTP host, addresses, and certificate path if needed and set up `authbind` accordingly. Then run `./bounce-padding-oracle.py`. |
| `header-decryption-oracle.py` | Header decryption-oracle PoC. | Install `uv` and the OpenSSL cli. Adjust the hard-coded SMTP host, addresses, and certificate path if needed and set up `authbind` accordingly. Then run `./header-decryption-oracle.py`. |
| `full-message-bounce.py` | Full-message-bounce PoC. | Install the OpenSSL cli, adjust the SMTP host and certificate path (CLI flags) if needed, then run `./full-message-bounce.py`. |
| `subject-tag.py` | Unicode subject-tag and bounded subject-tag sanitization PoC. | Adjust the hard-coded SMTP host and addresses if needed, then run `./subject-tag.py` (add `--unicode` for the Unicode variant). |
