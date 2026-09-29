# QSafe – Quantum-Readiness Toolkit

![tests](https://github.com/mithil2k2000-tech/qsafe/actions/workflows/tests.yml/badge.svg)

> Find the cryptography a quantum computer will break, and protect data with NIST post-quantum algorithms.

**The industry problem:** organisations can't find where they depend on RSA and
elliptic-curve cryptography, which a large quantum computer running Shor's algorithm
will break. Attackers can already record encrypted data now and decrypt it later
("harvest now, decrypt later"). The UK NCSC asks organisations to finish discovery and
planning by 2028, move their highest-priority systems by 2031 and finish migrating by 2035.

**QSafe does three things:**

| Part | Problem it tackles | Command |
|---|---|---|
| 1. **Scanner** (find) | "Where are we exposed?" Finds RSA/ECC/DH keys, certificates, SSH keys, code, weak TLS; gives a score + migration plan + CSV/JSON inventory | `scan` |
| 2. **File protection** (fix data at rest) | Encrypts and signs files with hybrid post-quantum crypto | `keygen` `encrypt` `decrypt` `sign` `verify` |
| 3. **Secure chat** (fix data in transit) | Quantum-safe key exchange with forward secrecy and server authentication | `chat-server` `chat-client` |

## Cryptography used (NIST standards, hybrid mode)

| Purpose | Post-quantum | + Classical | Notes |
|---|---|---|---|
| Key exchange | ML-KEM-768 (FIPS 203) | X25519 | Secrets combined with HKDF-SHA256; secure if *either* holds |
| Signatures | ML-DSA-65 (FIPS 204) | Ed25519 | Both must verify |
| Data | AES-256-GCM | | 1 MiB chunks, reorder/truncation-proof |
| Private keys at rest | scrypt + AES-256-GCM | | Password-protected `.key` files |

All primitives come from the `cryptography` library (OpenSSL); QSafe doesn't implement any algorithms itself.

## Setup (Windows)
1. Install Python 3.9+ from python.org (tick "Add to PATH").
2. Double-click `setup.bat` – it creates a virtual environment, installs dependencies, runs a self-test and builds a demo project.
3. Open a terminal in this folder and run `.venv\Scripts\activate`

## Quick start

```bat
:: 1. FIND - scan the demo project (or any folder of your own)
python qsafe.py scan demo_vulnerable_app --out my_report
python qsafe.py scan C:\path\to\project --tls www.example.com

:: 2. PROTECT FILES
python qsafe.py keygen alice
python qsafe.py keygen bob
python qsafe.py encrypt payroll.xlsx -r bob.pub --sign alice.key
python qsafe.py decrypt payroll.xlsx.qsafe -k bob.key --from alice.pub
python qsafe.py sign contract.pdf -k alice.key
python qsafe.py verify contract.pdf --from alice.pub

:: 3. SECURE CHAT (two terminals, or two PCs on the same network)
python qsafe.py chat-server -k alice.key --port 5050
python qsafe.py chat-client --server-pub alice.pub --host 127.0.0.1 --port 5050
```

Run the tests: `python test_qsafe.py` (13 tests, including tamper, truncation, wrong-key, forged-sender, man-in-the-middle and replay attacks).

## Example output

Scanning the included demo project (`python qsafe.py scan demo_vulnerable_app`):

```
Scanned 8 files
  CRITICAL 3   HIGH 9   MEDIUM 5   GOOD 3
  Quantum-readiness score: 38/100
```

| Risk | Finding | Location |
|---|---|---|
| CRITICAL | Certificate: RSA-2048 | `certs/server.crt` |
| CRITICAL | Private key: ECDSA/ECDH secp256r1 | `certs/signing_ec.key` |
| HIGH | JWT RSA/EC algorithm (RS256) | `src/auth.py:5` |
| HIGH | ECDSA / ECDH usage | `src/payments.js:3` |
| MEDIUM | Old TLS versions | `config/nginx.conf:4` |
| GOOD | Post-quantum algorithm (ML-KEM) | `src/new_vpn.py` |

Full sample report: [examples/sample_report.md](examples/sample_report.md)

## Project structure

| File | Purpose |
|---|---|
| `qsafe.py` | Command-line interface |
| `qsafe_core.py` | Hybrid KEM, signatures, file encryption, key storage |
| `qsafe_chat.py` | Secure chat protocol (handshake + encrypted channel) |
| `qsafe_scan.py` | Crypto-inventory scanner and report writer |
| `test_qsafe.py` | Automated tests, including attack simulations |
| `make_demo_app.py` | Builds a deliberately vulnerable demo project to scan |
| `.github/workflows/tests.yml` | Runs the tests on Windows, Linux and macOS on every push |

## Security notes (read these)
- Share `.pub` files freely; **never** share `.key` files. Confirm fingerprints over a separate channel (phone, in person) – this is what stops impersonation.
- Encrypted files reveal recipient names/fingerprints and (if signed) the signer's fingerprint, but never the contents.
- The chat client authenticates the server; the server does not authenticate the client (anyone with the address can connect). Add client keys before using it beyond a demo.
- This is a learning/portfolio project and hasn't had an independent security audit. For production, use audited products that support PQC (e.g. OpenSSL 3.5+ / TLS with X25519MLKEM768, OpenSSH 10 hybrid key exchange).

## Roadmap (ideas to grow it)
- Scanner: cloud certificates (AWS ACM / Azure Key Vault), Windows certificate store, CycloneDX CBOM export, HTML dashboard
- Detect the TLS key-exchange group directly (Python 3.13+ exposes it)
- Client authentication + multi-user chat
- Performance comparison page: RSA-3072 vs ML-KEM-768 sizes and speed
