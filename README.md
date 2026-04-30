# Artifacts

This repository contains proof-of-concept artifacts for _Delegating Email Encryption to Gateways: Why Johnny Should Not_. It includes only PoCs for issues where patches have been released.

## SEPPmail

| File | What it is | How to run/use |
|------|------------|----------------|
| `seppmail/mixed-plaintext-and-encrypted-content.py` | Mixed plaintext/encrypted-content PoC. | Install `pgpy`, adjust the hard-coded SMTP host, addresses, and key path if needed, then run `python3 seppmail/mixed-plaintext-and-encrypted-content.py`. |
| `seppmail/unicode-subject-tag.py` | Unicode subject-tag PoC. | Adjust the hard-coded SMTP host and addresses if needed, then run `python3 seppmail/unicode-subject-tag.py`. |
| `seppmail/bounded-subject-tag-sanitization.txt` | Subject-tag sanitization test string. | Use the text as a message subject or fixture input. |
| `seppmail/long-subject-untagging.py` | Long-subject S/MIME untagging PoC. | Install OpenSSL, adjust the hard-coded SMTP host, addresses, and certificate path if needed, then run `python3 seppmail/long-subject-untagging.py`. |

