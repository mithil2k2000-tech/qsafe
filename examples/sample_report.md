# Quantum-Readiness Report

- **Target:** `demo_vulnerable_app`
- **Scanned:** 2026-09-29 08:17 (8 files)
- **Quantum-readiness score:** 38/100

| Risk | Count | Meaning |
|---|---|---|
| CRITICAL | 3 | Keys/certificates breakable by a quantum computer (Shor) |
| HIGH | 9 | Code/config using RSA, ECC, DH, X25519/Ed25519 |
| MEDIUM | 5 | Weak or quantum-weakened crypto (MD5, SHA-1, AES-128, old TLS) |
| GOOD | 3 | Post-quantum crypto already present |

## Recommended migration order
1. **Long-lived secrets & key exchange** (TLS, VPN, file/database encryption) - exposed to *harvest now, decrypt later* today. Move to hybrid ML-KEM.
2. **Long-lived signatures** (root/intermediate CAs, firmware and code signing). Plan ML-DSA / SLH-DSA.
3. **Short-lived signatures and auth** (JWT, SSH user keys) once libraries and platforms support PQC.
4. **Clean-up**: remove MD5/SHA-1/3DES/RC4, move to AES-256 and SHA-384+.
5. **Crypto-agility**: centralise crypto config so algorithms can be swapped without code rewrites.

## Findings

| Risk | Finding | Location | Detail |
|---|---|---|---|
| CRITICAL | Certificate: RSA-2048 | `certs/server.crt` | subject=CN=shop.example-demo.local; expires=2029-01-01; sig=sha256 |
| CRITICAL | Private key: RSA-2048 | `certs/server.key` | Private key stored in file - also check it should be here at all |
| CRITICAL | Private key: ECDSA/ECDH secp256r1 | `certs/signing_ec.key` | Private key stored in file - also check it should be here at all |
| HIGH | SSH RSA public key | `config/authorized_keys:1` | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdemo admin@laptop |
| HIGH | SSH Ed25519 public key | `config/authorized_keys:2` | ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIdemo dev@workstation |
| HIGH | ECDSA / ECDH usage | `config/nginx.conf:5` | ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA; |
| HIGH | Diffie-Hellman usage | `config/nginx.conf:5` | ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA; |
| HIGH | Diffie-Hellman usage | `config/nginx.conf:6` | ssl_dhparam         /etc/ssl/dhparam.pem; |
| HIGH | RSA usage in code | `src/auth.py:11` | return rsa.generate_private_key(public_exponent=65537, key_size=2048) |
| HIGH | JWT RSA/EC algorithm | `src/auth.py:5` | return jwt.encode({"sub": user}, private_key, algorithm="RS256") |
| HIGH | ECDSA / ECDH usage | `src/payments.js:2` | const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }); |
| HIGH | ECDSA / ECDH usage | `src/payments.js:3` | const ecdh = crypto.createECDH("secp256k1");   // ECDH key agreement |
| MEDIUM | Old TLS versions | `config/nginx.conf:4` | ssl_protocols       TLSv1 TLSv1.1 TLSv1.2; |
| MEDIUM | DES / 3DES / RC4 | `config/nginx.conf:5` | ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA; |
| MEDIUM | AES-128 | `config/nginx.conf:5` | ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA; |
| MEDIUM | MD5 | `src/auth.py:8` | return hashlib.md5(pw.encode()).hexdigest()   # weak! |
| MEDIUM | AES-128 | `src/payments.js:4` | const cipher = crypto.createCipheriv("aes-128-cbc", key, iv); |
| GOOD | Post-quantum algorithm | `src/new_vpn.py:2` | from cryptography.hazmat.primitives.asymmetric import mlkem |
| GOOD | Post-quantum algorithm | `src/new_vpn.py:3` | KEX = "X25519MLKEM768" |
| GOOD | Post-quantum algorithm | `src/new_vpn.py:4` | kem = mlkem.MLKEM768PrivateKey.generate() |

## Advice by finding type

- **AES-128** - Use AES-256 (Grover's algorithm halves effective key strength); drop DES/3DES/RC4.
- **Certificate: RSA-2048** - Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.
- **DES / 3DES / RC4** - Use AES-256 (Grover's algorithm halves effective key strength); drop DES/3DES/RC4.
- **Diffie-Hellman usage** - Finite-field Diffie-Hellman is broken by Shor. Use hybrid X25519MLKEM768 key exchange.
- **ECDSA / ECDH usage** - ECDSA/ECDH are broken by Shor's algorithm. Move to ML-KEM (key exchange) / ML-DSA (signatures), hybrid during transition.
- **JWT RSA/EC algorithm** - Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.
- **MD5** - Replace MD5/SHA-1 with SHA-256 or better (SHA-384/512 for long-term).
- **Old TLS versions** - Disable TLS 1.0/1.1; require TLS 1.3 so post-quantum hybrid key exchange can be negotiated.
- **Post-quantum algorithm** - Post-quantum algorithm detected - good. Check it's the final FIPS 203/204/205 version and used in hybrid mode.
- **Private key: ECDSA/ECDH secp256r1** - ECDSA/ECDH are broken by Shor's algorithm. Move to ML-KEM (key exchange) / ML-DSA (signatures), hybrid during transition.
- **Private key: RSA-2048** - Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.
- **RSA usage in code** - Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.
- **SSH Ed25519 public key** - X25519/Ed25519 are elliptic-curve and quantum-vulnerable. Pair with ML-KEM-768 / ML-DSA-65 (hybrid).
- **SSH RSA public key** - Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.
