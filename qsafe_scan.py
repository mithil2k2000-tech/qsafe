"""
QSafe scanner: find quantum-vulnerable cryptography (crypto inventory).

Scans source code, configs, certificates, keys and SSH files and reports:
  CRITICAL - private keys / certificates using RSA, ECC, DSA, DH (breakable by Shor)
  HIGH     - code/config that uses RSA, ECDSA, ECDH, DH, Ed25519, X25519
  MEDIUM   - classically weak or quantum-weakened crypto (MD5, SHA-1, DES, RC4, AES-128, old TLS)
  GOOD     - post-quantum algorithms already in use (ML-KEM, ML-DSA, SLH-DSA, ...)

Outputs: console summary, Markdown report, CSV, and a JSON crypto inventory (CBOM-style).
"""
import csv, datetime, json, os, re, socket, ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, ed25519, ed448, x25519, x448

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode",
             "dist", "build", ".tox", ".mypy_cache", "site-packages"}
MAX_BYTES = 5 * 1024 * 1024
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "GOOD": 3}

ADVICE = {
    "rsa": "Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.",
    "ecc": "ECDSA/ECDH are broken by Shor's algorithm. Move to ML-KEM (key exchange) / ML-DSA (signatures), hybrid during transition.",
    "25519": "X25519/Ed25519 are elliptic-curve and quantum-vulnerable. Pair with ML-KEM-768 / ML-DSA-65 (hybrid).",
    "dh": "Finite-field Diffie-Hellman is broken by Shor. Use hybrid X25519MLKEM768 key exchange.",
    "dsa": "DSA is deprecated and quantum-vulnerable. Migrate to ML-DSA or SLH-DSA.",
    "hash": "Replace MD5/SHA-1 with SHA-256 or better (SHA-384/512 for long-term).",
    "sym": "Use AES-256 (Grover's algorithm halves effective key strength); drop DES/3DES/RC4.",
    "tls": "Disable TLS 1.0/1.1; require TLS 1.3 so post-quantum hybrid key exchange can be negotiated.",
    "pqc": "Post-quantum algorithm detected - good. Check it's the final FIPS 203/204/205 version and used in hybrid mode.",
}

# (id, regex, flags, risk, category, advice-key)
PATTERNS = [
    ("RSA private key (PEM)", r"-----BEGIN RSA PRIVATE KEY-----", 0, "CRITICAL", "key-material", "rsa"),
    ("EC private key (PEM)", r"-----BEGIN EC PRIVATE KEY-----", 0, "CRITICAL", "key-material", "ecc"),
    ("DSA private key (PEM)", r"-----BEGIN DSA PRIVATE KEY-----", 0, "CRITICAL", "key-material", "dsa"),
    ("SSH RSA public key", r"\bssh-rsa AAAA", 0, "HIGH", "ssh", "rsa"),
    ("SSH DSA public key", r"\bssh-dss AAAA", 0, "HIGH", "ssh", "dsa"),
    ("SSH ECDSA public key", r"\becdsa-sha2-nistp\d+ AAAA", 0, "HIGH", "ssh", "ecc"),
    ("SSH Ed25519 public key", r"\bssh-ed25519 AAAA", 0, "HIGH", "ssh", "25519"),
    ("RSA usage in code", r"\bRSA_generate_key|generate_private_key\(\s*public_exponent|getInstance\(\s*\"RSA|"
                          r"generateKeyPair(Sync)?\(\s*['\"]rsa|Crypto\.PublicKey import RSA|\bRSA\.generate\(|"
                          r"\brsa\.GenerateKey|RSACryptoServiceProvider|RSA\.Create\(|\bRSA-OAEP\b|\bRSA_PKCS1|PKCS1v15|\bRSASSA", 0, "HIGH", "code", "rsa"),
    ("JWT RSA/EC algorithm", r"['\"](RS|PS|ES)(256|384|512)['\"]", 0, "HIGH", "code", "rsa"),
    ("ECDSA / ECDH usage", r"\bECDSA\b|\bECDH[E]?\b|ec\.generate_private_key|\bsecp(256|384|521)[rk]1\b|\bprime256v1\b|"
                           r"\bP-(256|384|521)\b|elliptic\.P(256|384|521)|ECDsa|ECDiffieHellman|getInstance\(\s*\"EC", 0, "HIGH", "code", "ecc"),
    ("X25519 / Ed25519 usage", r"\b[XE]d?25519\b|\bCurve25519\b|\bEdDSA\b|\bX448\b|\bEd448\b", 0, "HIGH", "code", "25519"),
    ("Diffie-Hellman usage", r"\bDiffieHellman\b|dh\.generate_parameters|\bDHE-RSA|\bffdhe\d+|\bdhparam", 0, "HIGH", "code", "dh"),
    ("DSA usage", r"getInstance\(\s*\"DSA|dsa\.generate_private_key|DSACryptoServiceProvider", 0, "HIGH", "code", "dsa"),
    ("MD5", r"\bmd5\b|\bMD5\(|hashlib\.md5|MessageDigest\.getInstance\(\s*\"MD5", re.I, "MEDIUM", "hash", "hash"),
    ("SHA-1", r"hashlib\.sha1|\bSHA-?1\b|getInstance\(\s*\"SHA-?1|\bsha1WithRSA", 0, "MEDIUM", "hash", "hash"),
    ("DES / 3DES / RC4", r"\b3DES\b|\bTripleDES\b|\bDESede\b|\bDES-CBC|\bRC4\b|\bARC4\b", 0, "MEDIUM", "symmetric", "sym"),
    ("AES-128", r"\bAES[-_]?128\b|aes-128-", re.I, "MEDIUM", "symmetric", "sym"),
    ("Old TLS versions", r"\bTLSv1(\.0|\.1)?\b(?!\.[23])|\bSSLv[23]\b|PROTOCOL_TLSv1(_1)?\b", 0, "MEDIUM", "tls", "tls"),
    ("Post-quantum algorithm", r"\bML-?KEM|\bKyber\d*|\bML-?DSA|\bDilithium\d*|\bSLH-?DSA|\bSPHINCS\+?|\bFalcon-?\d+|"
                               r"X25519MLKEM768|X25519Kyber768|\bmlkem\b|\bmldsa\b", re.I, "GOOD", "pqc", "pqc"),
]
COMPILED = [(n, re.compile(rx, fl), risk, cat, adv) for n, rx, fl, risk, cat, adv in PATTERNS]
PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)
CERT_EXT = {".pem", ".crt", ".cer", ".der", ".key", ".pub"}


def key_info(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}", "rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA/ECDH {pub.curve.name}", "ecc"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA-{pub.key_size}", "dsa"
    if isinstance(pub, dh.DHPublicKey):
        return f"DH-{pub.key_size}", "dh"
    if isinstance(pub, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey, ed448.Ed448PublicKey, x448.X448PublicKey)):
        return type(pub).__name__.replace("PublicKey", ""), "25519"
    name = type(pub).__name__
    if "MLDSA" in name or "MLKEM" in name or "SLH" in name:
        return name.replace("PublicKey", ""), "pqc"
    return name, None


def analyse_cert(cert, where):
    out = []
    alg, adv = key_info(cert.public_key())
    try:
        exp = cert.not_valid_after_utc
    except AttributeError:
        exp = cert.not_valid_after
    subject = cert.subject.rfc4514_string()[:80]
    risk = "GOOD" if adv == "pqc" else ("CRITICAL" if adv else "MEDIUM")
    out.append(dict(risk=risk, finding=f"Certificate: {alg}", category="certificate", location=where,
                    detail=f"subject={subject}; expires={exp:%Y-%m-%d}; sig={getattr(cert.signature_hash_algorithm, 'name', '?')}",
                    advice=ADVICE.get(adv, "")))
    h = getattr(cert.signature_hash_algorithm, "name", "")
    if h in ("md5", "sha1"):
        out.append(dict(risk="MEDIUM", finding=f"Certificate signed with {h.upper()}", category="certificate",
                        location=where, detail=subject, advice=ADVICE["hash"]))
    return out


def analyse_pem_blocks(data: bytes, where):
    out = []
    for m in PEM_BLOCK.finditer(data):
        kind, blob = m.group(1).decode(), m.group(0)
        try:
            if kind == "CERTIFICATE":
                out += analyse_cert(x509.load_pem_x509_certificate(blob), where)
            elif kind == "PUBLIC KEY":
                alg, adv = key_info(serialization.load_pem_public_key(blob))
                if adv:
                    out.append(dict(risk="GOOD" if adv == "pqc" else "HIGH", finding=f"Public key: {alg}",
                                    category="key-material", location=where, detail="", advice=ADVICE[adv]))
            elif kind in ("PRIVATE KEY", "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"):
                try:
                    k = (serialization.load_ssh_private_key(blob, None) if "OPENSSH" in kind
                         else serialization.load_pem_private_key(blob, None))
                    alg, adv = key_info(k.public_key())
                except TypeError:   # password protected
                    alg, adv = "encrypted private key (type hidden)", "rsa"
                if adv:
                    out.append(dict(risk="GOOD" if adv == "pqc" else "CRITICAL", finding=f"Private key: {alg}",
                                    category="key-material", location=where,
                                    detail="Private key stored in file - also check it should be here at all",
                                    advice=ADVICE[adv]))
            elif kind == "ENCRYPTED PRIVATE KEY":
                out.append(dict(risk="CRITICAL", finding="Encrypted private key (algorithm unknown)", category="key-material",
                                location=where, detail="Decrypt to identify; likely RSA/ECC", advice=ADVICE["rsa"]))
        except Exception as e:
            out.append(dict(risk="MEDIUM", finding=f"Unparseable PEM block: {kind}", category="key-material",
                            location=where, detail=str(e)[:80], advice="Review manually"))
    return out


def scan_file(path, root):
    rel = os.path.relpath(path, root)
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    ext = os.path.splitext(path)[1].lower()
    findings = []
    if ext in (".der", ".cer", ".crt") and not data.lstrip().startswith(b"-----"):
        try:
            return analyse_cert(x509.load_der_x509_certificate(data), rel)
        except Exception:
            pass
    if b"\x00" in data[:8192]:
        return []   # binary
    if b"-----BEGIN" in data:
        findings += analyse_pem_blocks(data, rel)
    text = data.decode("utf-8", "replace")
    parsed_pem = bool(findings)
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for name, rx, risk, cat, adv in COMPILED:
            if cat == "key-material" and parsed_pem:
                continue
            m = rx.search(line)
            if m:
                findings.append(dict(risk=risk, finding=name, category=cat, location=f"{rel}:{lineno}",
                                     detail=line.strip()[:120], advice=ADVICE[adv]))
    return findings


def scan_path(root):
    root = os.path.abspath(root)
    findings, files = [], 0
    if os.path.isfile(root):
        return scan_file(root, os.path.dirname(root)), 1
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            files += 1
            findings += scan_file(os.path.join(dirpath, fn), root)
    return findings, files


def scan_tls(host, port=443):
    """Check a live server: TLS version, cipher and certificate key type."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
            version, cipher = t.version(), t.cipher()[0]
            group = t.group() if hasattr(t, "group") else None   # Python 3.13+/OpenSSL 3.5
    where = f"{host}:{port}"
    out = analyse_cert(x509.load_der_x509_certificate(der), where)
    out.append(dict(risk="MEDIUM" if version in ("TLSv1", "TLSv1.1") else "GOOD", finding=f"TLS version {version}",
                    category="tls", location=where, detail=f"cipher={cipher}",
                    advice=ADVICE["tls"] if version != "TLSv1.3" else "TLS 1.3 in use."))
    if group:
        pq = "MLKEM" in group.upper() or "KYBER" in group.upper()
        out.append(dict(risk="GOOD" if pq else "HIGH", finding=f"Key exchange group {group}", category="tls",
                        location=where, detail="", advice=ADVICE["pqc"] if pq else ADVICE["25519"]))
    else:
        out.append(dict(risk="HIGH", finding="Key exchange group not visible from this Python/OpenSSL",
                        category="tls", location=where,
                        detail="Assume classical ECDHE unless server confirms X25519MLKEM768",
                        advice="Enable X25519MLKEM768 on the server/load balancer (OpenSSL 3.5+, recent nginx/Cloudflare/AWS)."))
    return out


def summarise(findings):
    counts = {k: 0 for k in RISK_ORDER}
    for f in findings:
        counts[f["risk"]] += 1
    vulnerable = counts["CRITICAL"] + counts["HIGH"]
    score = max(0, 100 - counts["CRITICAL"] * 10 - counts["HIGH"] * 3 - counts["MEDIUM"])
    return counts, vulnerable, score


def write_reports(findings, target, files, out_prefix):
    findings.sort(key=lambda f: (RISK_ORDER[f["risk"]], f["location"]))
    counts, vulnerable, score = summarise(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(out_prefix + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["risk", "finding", "category", "location", "detail", "advice"])
        w.writeheader(); w.writerows(findings)
    inventory = {"tool": "QSafe scanner", "generated": now, "target": target, "files_scanned": files,
                 "summary": counts, "quantum_readiness_score": score, "assets": findings}
    with open(out_prefix + ".json", "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    L = [f"# Quantum-Readiness Report", "", f"- **Target:** `{target}`", f"- **Scanned:** {now} ({files} files)",
         f"- **Quantum-readiness score:** {score}/100", "",
         "| Risk | Count | Meaning |", "|---|---|---|",
         f"| CRITICAL | {counts['CRITICAL']} | Keys/certificates breakable by a quantum computer (Shor) |",
         f"| HIGH | {counts['HIGH']} | Code/config using RSA, ECC, DH, X25519/Ed25519 |",
         f"| MEDIUM | {counts['MEDIUM']} | Weak or quantum-weakened crypto (MD5, SHA-1, AES-128, old TLS) |",
         f"| GOOD | {counts['GOOD']} | Post-quantum crypto already present |", "",
         "## Recommended migration order",
         "1. **Long-lived secrets & key exchange** (TLS, VPN, file/database encryption) - exposed to *harvest now, decrypt later* today. Move to hybrid ML-KEM.",
         "2. **Long-lived signatures** (root/intermediate CAs, firmware and code signing). Plan ML-DSA / SLH-DSA.",
         "3. **Short-lived signatures and auth** (JWT, SSH user keys) once libraries and platforms support PQC.",
         "4. **Clean-up**: remove MD5/SHA-1/3DES/RC4, move to AES-256 and SHA-384+.",
         "5. **Crypto-agility**: centralise crypto config so algorithms can be swapped without code rewrites.", "",
         "## Findings", "", "| Risk | Finding | Location | Detail |", "|---|---|---|---|"]
    for f in findings:
        d = f["detail"].replace("|", "\\|").replace("`", "'")
        L.append(f"| {f['risk']} | {f['finding']} | `{f['location']}` | {d} |")
    L += ["", "## Advice by finding type", ""]
    for name in sorted({(f["finding"], f["advice"]) for f in findings if f["advice"]}):
        L.append(f"- **{name[0]}** - {name[1]}")
    with open(out_prefix + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    from qsafe_dashboard import write_dashboard
    write_dashboard(findings, target, files, out_prefix, counts, score, now)
    return counts, vulnerable, score
"""
QSafe scanner: find quantum-vulnerable cryptography (crypto inventory).

Scans source code, configs, certificates, keys and SSH files and reports:
  CRITICAL - private keys / certificates using RSA, ECC, DSA, DH (breakable by Shor)
  HIGH     - code/config that uses RSA, ECDSA, ECDH, DH, Ed25519, X25519
  MEDIUM   - classically weak or quantum-weakened crypto (MD5, SHA-1, DES, RC4, AES-128, old TLS)
  GOOD     - post-quantum algorithms already in use (ML-KEM, ML-DSA, SLH-DSA, ...)

Outputs: console summary, Markdown report, CSV, and a JSON crypto inventory (CBOM-style).
"""
import csv, datetime, json, os, re, socket, ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, ed25519, ed448, x25519, x448

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode",
             "dist", "build", ".tox", ".mypy_cache", "site-packages"}
MAX_BYTES = 5 * 1024 * 1024
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "GOOD": 3}

ADVICE = {
    "rsa": "Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.",
    "ecc": "ECDSA/ECDH are broken by Shor's algorithm. Move to ML-KEM (key exchange) / ML-DSA (signatures), hybrid during transition.",
    "25519": "X25519/Ed25519 are elliptic-curve and quantum-vulnerable. Pair with ML-KEM-768 / ML-DSA-65 (hybrid).",
    "dh": "Finite-field Diffie-Hellman is broken by Shor. Use hybrid X25519MLKEM768 key exchange.",
    "dsa": "DSA is deprecated and quantum-vulnerable. Migrate to ML-DSA or SLH-DSA.",
    "hash": "Replace MD5/SHA-1 with SHA-256 or better (SHA-384/512 for long-term).",
    "sym": "Use AES-256 (Grover's algorithm halves effective key strength); drop DES/3DES/RC4.",
    "tls": "Disable TLS 1.0/1.1; require TLS 1.3 so post-quantum hybrid key exchange can be negotiated.",
    "pqc": "Post-quantum algorithm detected - good. Check it's the final FIPS 203/204/205 version and used in hybrid mode.",
}

# (id, regex, flags, risk, category, advice-key)
PATTERNS = [
    ("RSA private key (PEM)", r"-----BEGIN RSA PRIVATE KEY-----", 0, "CRITICAL", "key-material", "rsa"),
    ("EC private key (PEM)", r"-----BEGIN EC PRIVATE KEY-----", 0, "CRITICAL", "key-material", "ecc"),
    ("DSA private key (PEM)", r"-----BEGIN DSA PRIVATE KEY-----", 0, "CRITICAL", "key-material", "dsa"),
    ("SSH RSA public key", r"\bssh-rsa AAAA", 0, "HIGH", "ssh", "rsa"),
    ("SSH DSA public key", r"\bssh-dss AAAA", 0, "HIGH", "ssh", "dsa"),
    ("SSH ECDSA public key", r"\becdsa-sha2-nistp\d+ AAAA", 0, "HIGH", "ssh", "ecc"),
    ("SSH Ed25519 public key", r"\bssh-ed25519 AAAA", 0, "HIGH", "ssh", "25519"),
    ("RSA usage in code", r"\bRSA_generate_key|generate_private_key\(\s*public_exponent|getInstance\(\s*\"RSA|"
                          r"generateKeyPair(Sync)?\(\s*['\"]rsa|Crypto\.PublicKey import RSA|\bRSA\.generate\(|"
                          r"\brsa\.GenerateKey|RSACryptoServiceProvider|RSA\.Create\(|\bRSA-OAEP\b|\bRSA_PKCS1|PKCS1v15|\bRSASSA", 0, "HIGH", "code", "rsa"),
    ("JWT RSA/EC algorithm", r"['\"](RS|PS|ES)(256|384|512)['\"]", 0, "HIGH", "code", "rsa"),
    ("ECDSA / ECDH usage", r"\bECDSA\b|\bECDH[E]?\b|ec\.generate_private_key|\bsecp(256|384|521)[rk]1\b|\bprime256v1\b|"
                           r"\bP-(256|384|521)\b|elliptic\.P(256|384|521)|ECDsa|ECDiffieHellman|getInstance\(\s*\"EC", 0, "HIGH", "code", "ecc"),
    ("X25519 / Ed25519 usage", r"\b[XE]d?25519\b|\bCurve25519\b|\bEdDSA\b|\bX448\b|\bEd448\b", 0, "HIGH", "code", "25519"),
    ("Diffie-Hellman usage", r"\bDiffieHellman\b|dh\.generate_parameters|\bDHE-RSA|\bffdhe\d+|\bdhparam", 0, "HIGH", "code", "dh"),
    ("DSA usage", r"getInstance\(\s*\"DSA|dsa\.generate_private_key|DSACryptoServiceProvider", 0, "HIGH", "code", "dsa"),
    ("MD5", r"\bmd5\b|\bMD5\(|hashlib\.md5|MessageDigest\.getInstance\(\s*\"MD5", re.I, "MEDIUM", "hash", "hash"),
    ("SHA-1", r"hashlib\.sha1|\bSHA-?1\b|getInstance\(\s*\"SHA-?1|\bsha1WithRSA", 0, "MEDIUM", "hash", "hash"),
    ("DES / 3DES / RC4", r"\b3DES\b|\bTripleDES\b|\bDESede\b|\bDES-CBC|\bRC4\b|\bARC4\b", 0, "MEDIUM", "symmetric", "sym"),
    ("AES-128", r"\bAES[-_]?128\b|aes-128-", re.I, "MEDIUM", "symmetric", "sym"),
    ("Old TLS versions", r"\bTLSv1(\.0|\.1)?\b(?!\.[23])|\bSSLv[23]\b|PROTOCOL_TLSv1(_1)?\b", 0, "MEDIUM", "tls", "tls"),
    ("Post-quantum algorithm", r"\bML-?KEM|\bKyber\d*|\bML-?DSA|\bDilithium\d*|\bSLH-?DSA|\bSPHINCS\+?|\bFalcon-?\d+|"
                               r"X25519MLKEM768|X25519Kyber768|\bmlkem\b|\bmldsa\b", re.I, "GOOD", "pqc", "pqc"),
]
COMPILED = [(n, re.compile(rx, fl), risk, cat, adv) for n, rx, fl, risk, cat, adv in PATTERNS]
PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)
CERT_EXT = {".pem", ".crt", ".cer", ".der", ".key", ".pub"}


def key_info(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}", "rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA/ECDH {pub.curve.name}", "ecc"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA-{pub.key_size}", "dsa"
    if isinstance(pub, dh.DHPublicKey):
        return f"DH-{pub.key_size}", "dh"
    if isinstance(pub, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey, ed448.Ed448PublicKey, x448.X448PublicKey)):
        return type(pub).__name__.replace("PublicKey", ""), "25519"
    name = type(pub).__name__
    if "MLDSA" in name or "MLKEM" in name or "SLH" in name:
        return name.replace("PublicKey", ""), "pqc"
    return name, None


def analyse_cert(cert, where):
    out = []
    alg, adv = key_info(cert.public_key())
    try:
        exp = cert.not_valid_after_utc
    except AttributeError:
        exp = cert.not_valid_after
    subject = cert.subject.rfc4514_string()[:80]
    risk = "GOOD" if adv == "pqc" else ("CRITICAL" if adv else "MEDIUM")
    out.append(dict(risk=risk, finding=f"Certificate: {alg}", category="certificate", location=where,
                    detail=f"subject={subject}; expires={exp:%Y-%m-%d}; sig={getattr(cert.signature_hash_algorithm, 'name', '?')}",
                    advice=ADVICE.get(adv, "")))
    h = getattr(cert.signature_hash_algorithm, "name", "")
    if h in ("md5", "sha1"):
        out.append(dict(risk="MEDIUM", finding=f"Certificate signed with {h.upper()}", category="certificate",
                        location=where, detail=subject, advice=ADVICE["hash"]))
    return out


def analyse_pem_blocks(data: bytes, where):
    out = []
    for m in PEM_BLOCK.finditer(data):
        kind, blob = m.group(1).decode(), m.group(0)
        try:
            if kind == "CERTIFICATE":
                out += analyse_cert(x509.load_pem_x509_certificate(blob), where)
            elif kind == "PUBLIC KEY":
                alg, adv = key_info(serialization.load_pem_public_key(blob))
                if adv:
                    out.append(dict(risk="GOOD" if adv == "pqc" else "HIGH", finding=f"Public key: {alg}",
                                    category="key-material", location=where, detail="", advice=ADVICE[adv]))
            elif kind in ("PRIVATE KEY", "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"):
                try:
                    k = (serialization.load_ssh_private_key(blob, None) if "OPENSSH" in kind
                         else serialization.load_pem_private_key(blob, None))
                    alg, adv = key_info(k.public_key())
                except TypeError:   # password protected
                    alg, adv = "encrypted private key (type hidden)", "rsa"
                if adv:
                    out.append(dict(risk="GOOD" if adv == "pqc" else "CRITICAL", finding=f"Private key: {alg}",
                                    category="key-material", location=where,
                                    detail="Private key stored in file - also check it should be here at all",
                                    advice=ADVICE[adv]))
            elif kind == "ENCRYPTED PRIVATE KEY":
                out.append(dict(risk="CRITICAL", finding="Encrypted private key (algorithm unknown)", category="key-material",
                                location=where, detail="Decrypt to identify; likely RSA/ECC", advice=ADVICE["rsa"]))
        except Exception as e:
            out.append(dict(risk="MEDIUM", finding=f"Unparseable PEM block: {kind}", category="key-material",
                            location=where, detail=str(e)[:80], advice="Review manually"))
    return out


def scan_file(path, root):
    rel = os.path.relpath(path, root)
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    ext = os.path.splitext(path)[1].lower()
    findings = []
    if ext in (".der", ".cer", ".crt") and not data.lstrip().startswith(b"-----"):
        try:
            return analyse_cert(x509.load_der_x509_certificate(data), rel)
        except Exception:
            pass
    if b"\x00" in data[:8192]:
        return []   # binary
    if b"-----BEGIN" in data:
        findings += analyse_pem_blocks(data, rel)
    text = data.decode("utf-8", "replace")
    parsed_pem = bool(findings)
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for name, rx, risk, cat, adv in COMPILED:
            if cat == "key-material" and parsed_pem:
                continue
            m = rx.search(line)
            if m:
                findings.append(dict(risk=risk, finding=name, category=cat, location=f"{rel}:{lineno}",
                                     detail=line.strip()[:120], advice=ADVICE[adv]))
    return findings


def scan_path(root):
    root = os.path.abspath(root)
    findings, files = [], 0
    if os.path.isfile(root):
        return scan_file(root, os.path.dirname(root)), 1
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            files += 1
            findings += scan_file(os.path.join(dirpath, fn), root)
    return findings, files


def scan_tls(host, port=443):
    """Check a live server: TLS version, cipher and certificate key type."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
            version, cipher = t.version(), t.cipher()[0]
            group = t.group() if hasattr(t, "group") else None   # Python 3.13+/OpenSSL 3.5
    where = f"{host}:{port}"
    out = analyse_cert(x509.load_der_x509_certificate(der), where)
    out.append(dict(risk="MEDIUM" if version in ("TLSv1", "TLSv1.1") else "GOOD", finding=f"TLS version {version}",
                    category="tls", location=where, detail=f"cipher={cipher}",
                    advice=ADVICE["tls"] if version != "TLSv1.3" else "TLS 1.3 in use."))
    if group:
        pq = "MLKEM" in group.upper() or "KYBER" in group.upper()
        out.append(dict(risk="GOOD" if pq else "HIGH", finding=f"Key exchange group {group}", category="tls",
                        location=where, detail="", advice=ADVICE["pqc"] if pq else ADVICE["25519"]))
    else:
        out.append(dict(risk="HIGH", finding="Key exchange group not visible from this Python/OpenSSL",
                        category="tls", location=where,
                        detail="Assume classical ECDHE unless server confirms X25519MLKEM768",
                        advice="Enable X25519MLKEM768 on the server/load balancer (OpenSSL 3.5+, recent nginx/Cloudflare/AWS)."))
    return out


def summarise(findings):
    counts = {k: 0 for k in RISK_ORDER}
    for f in findings:
        counts[f["risk"]] += 1
    vulnerable = counts["CRITICAL"] + counts["HIGH"]
    score = max(0, 100 - counts["CRITICAL"] * 10 - counts["HIGH"] * 3 - counts["MEDIUM"])
    return counts, vulnerable, score


def write_reports(findings, target, files, out_prefix):
    findings.sort(key=lambda f: (RISK_ORDER[f["risk"]], f["location"]))
    counts, vulnerable, score = summarise(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(out_prefix + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["risk", "finding", "category", "location", "detail", "advice"])
        w.writeheader(); w.writerows(findings)
    inventory = {"tool": "QSafe scanner", "generated": now, "target": target, "files_scanned": files,
                 "summary": counts, "quantum_readiness_score": score, "assets": findings}
    with open(out_prefix + ".json", "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    L = [f"# Quantum-Readiness Report", "", f"- **Target:** `{target}`", f"- **Scanned:** {now} ({files} files)",
         f"- **Quantum-readiness score:** {score}/100", "",
         "| Risk | Count | Meaning |", "|---|---|---|",
         f"| CRITICAL | {counts['CRITICAL']} | Keys/certificates breakable by a quantum computer (Shor) |",
         f"| HIGH | {counts['HIGH']} | Code/config using RSA, ECC, DH, X25519/Ed25519 |",
         f"| MEDIUM | {counts['MEDIUM']} | Weak or quantum-weakened crypto (MD5, SHA-1, AES-128, old TLS) |",
         f"| GOOD | {counts['GOOD']} | Post-quantum crypto already present |", "",
         "## Recommended migration order",
         "1. **Long-lived secrets & key exchange** (TLS, VPN, file/database encryption) - exposed to *harvest now, decrypt later* today. Move to hybrid ML-KEM.",
         "2. **Long-lived signatures** (root/intermediate CAs, firmware and code signing). Plan ML-DSA / SLH-DSA.",
         "3. **Short-lived signatures and auth** (JWT, SSH user keys) once libraries and platforms support PQC.",
         "4. **Clean-up**: remove MD5/SHA-1/3DES/RC4, move to AES-256 and SHA-384+.",
         "5. **Crypto-agility**: centralise crypto config so algorithms can be swapped without code rewrites.", "",
         "## Findings", "", "| Risk | Finding | Location | Detail |", "|---|---|---|---|"]
    for f in findings:
        d = f["detail"].replace("|", "\\|").replace("`", "'")
        L.append(f"| {f['risk']} | {f['finding']} | `{f['location']}` | {d} |")
    L += ["", "## Advice by finding type", ""]
    for name in sorted({(f["finding"], f["advice"]) for f in findings if f["advice"]}):
        L.append(f"- **{name[0]}** - {name[1]}")
    with open(out_prefix + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    from qsafe_dashboard import write_dashboard
    write_dashboard(findings, target, files, out_prefix, counts, score, now)
    return counts, vulnerable, score
"""
QSafe scanner: find quantum-vulnerable cryptography (crypto inventory).

Scans source code, configs, certificates, keys and SSH files and reports:
  CRITICAL - private keys / certificates using RSA, ECC, DSA, DH (breakable by Shor)
  HIGH     - code/config that uses RSA, ECDSA, ECDH, DH, Ed25519, X25519
  MEDIUM   - classically weak or quantum-weakened crypto (MD5, SHA-1, DES, RC4, AES-128, old TLS)
  GOOD     - post-quantum algorithms already in use (ML-KEM, ML-DSA, SLH-DSA, ...)

Outputs: console summary, Markdown report, CSV, and a JSON crypto inventory (CBOM-style).
"""
import csv, datetime, json, os, re, socket, ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh, ed25519, ed448, x25519, x448

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode",
             "dist", "build", ".tox", ".mypy_cache", "site-packages"}
MAX_BYTES = 5 * 1024 * 1024
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "GOOD": 3}

ADVICE = {
    "rsa": "Replace RSA key exchange with ML-KEM (hybrid X25519MLKEM768); replace RSA signatures with ML-DSA.",
    "ecc": "ECDSA/ECDH are broken by Shor's algorithm. Move to ML-KEM (key exchange) / ML-DSA (signatures), hybrid during transition.",
    "25519": "X25519/Ed25519 are elliptic-curve and quantum-vulnerable. Pair with ML-KEM-768 / ML-DSA-65 (hybrid).",
    "dh": "Finite-field Diffie-Hellman is broken by Shor. Use hybrid X25519MLKEM768 key exchange.",
    "dsa": "DSA is deprecated and quantum-vulnerable. Migrate to ML-DSA or SLH-DSA.",
    "hash": "Replace MD5/SHA-1 with SHA-256 or better (SHA-384/512 for long-term).",
    "sym": "Use AES-256 (Grover's algorithm halves effective key strength); drop DES/3DES/RC4.",
    "tls": "Disable TLS 1.0/1.1; require TLS 1.3 so post-quantum hybrid key exchange can be negotiated.",
    "pqc": "Post-quantum algorithm detected - good. Check it's the final FIPS 203/204/205 version and used in hybrid mode.",
}

# (id, regex, flags, risk, category, advice-key)
PATTERNS = [
    ("RSA private key (PEM)", r"-----BEGIN RSA PRIVATE KEY-----", 0, "CRITICAL", "key-material", "rsa"),
    ("EC private key (PEM)", r"-----BEGIN EC PRIVATE KEY-----", 0, "CRITICAL", "key-material", "ecc"),
    ("DSA private key (PEM)", r"-----BEGIN DSA PRIVATE KEY-----", 0, "CRITICAL", "key-material", "dsa"),
    ("SSH RSA public key", r"\bssh-rsa AAAA", 0, "HIGH", "ssh", "rsa"),
    ("SSH DSA public key", r"\bssh-dss AAAA", 0, "HIGH", "ssh", "dsa"),
    ("SSH ECDSA public key", r"\becdsa-sha2-nistp\d+ AAAA", 0, "HIGH", "ssh", "ecc"),
    ("SSH Ed25519 public key", r"\bssh-ed25519 AAAA", 0, "HIGH", "ssh", "25519"),
    ("RSA usage in code", r"\bRSA_generate_key|generate_private_key\(\s*public_exponent|getInstance\(\s*\"RSA|"
                          r"generateKeyPair(Sync)?\(\s*['\"]rsa|Crypto\.PublicKey import RSA|\bRSA\.generate\(|"
                          r"\brsa\.GenerateKey|RSACryptoServiceProvider|RSA\.Create\(|\bRSA-OAEP\b|\bRSA_PKCS1|PKCS1v15|\bRSASSA", 0, "HIGH", "code", "rsa"),
    ("JWT RSA/EC algorithm", r"['\"](RS|PS|ES)(256|384|512)['\"]", 0, "HIGH", "code", "rsa"),
    ("ECDSA / ECDH usage", r"\bECDSA\b|\bECDH[E]?\b|ec\.generate_private_key|\bsecp(256|384|521)[rk]1\b|\bprime256v1\b|"
                           r"\bP-(256|384|521)\b|elliptic\.P(256|384|521)|ECDsa|ECDiffieHellman|getInstance\(\s*\"EC", 0, "HIGH", "code", "ecc"),
    ("X25519 / Ed25519 usage", r"\b[XE]d?25519\b|\bCurve25519\b|\bEdDSA\b|\bX448\b|\bEd448\b", 0, "HIGH", "code", "25519"),
    ("Diffie-Hellman usage", r"\bDiffieHellman\b|dh\.generate_parameters|\bDHE-RSA|\bffdhe\d+|\bdhparam", 0, "HIGH", "code", "dh"),
    ("DSA usage", r"getInstance\(\s*\"DSA|dsa\.generate_private_key|DSACryptoServiceProvider", 0, "HIGH", "code", "dsa"),
    ("MD5", r"\bmd5\b|\bMD5\(|hashlib\.md5|MessageDigest\.getInstance\(\s*\"MD5", re.I, "MEDIUM", "hash", "hash"),
    ("SHA-1", r"hashlib\.sha1|\bSHA-?1\b|getInstance\(\s*\"SHA-?1|\bsha1WithRSA", 0, "MEDIUM", "hash", "hash"),
    ("DES / 3DES / RC4", r"\b3DES\b|\bTripleDES\b|\bDESede\b|\bDES-CBC|\bRC4\b|\bARC4\b", 0, "MEDIUM", "symmetric", "sym"),
    ("AES-128", r"\bAES[-_]?128\b|aes-128-", re.I, "MEDIUM", "symmetric", "sym"),
    ("Old TLS versions", r"\bTLSv1(\.0|\.1)?\b(?!\.[23])|\bSSLv[23]\b|PROTOCOL_TLSv1(_1)?\b", 0, "MEDIUM", "tls", "tls"),
    ("Post-quantum algorithm", r"\bML-?KEM|\bKyber\d*|\bML-?DSA|\bDilithium\d*|\bSLH-?DSA|\bSPHINCS\+?|\bFalcon-?\d+|"
                               r"X25519MLKEM768|X25519Kyber768|\bmlkem\b|\bmldsa\b", re.I, "GOOD", "pqc", "pqc"),
]
COMPILED = [(n, re.compile(rx, fl), risk, cat, adv) for n, rx, fl, risk, cat, adv in PATTERNS]
PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)
CERT_EXT = {".pem", ".crt", ".cer", ".der", ".key", ".pub"}


def key_info(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}", "rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"ECDSA/ECDH {pub.curve.name}", "ecc"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA-{pub.key_size}", "dsa"
    if isinstance(pub, dh.DHPublicKey):
        return f"DH-{pub.key_size}", "dh"
    if isinstance(pub, (ed25519.Ed25519PublicKey, x25519.X25519PublicKey, ed448.Ed448PublicKey, x448.X448PublicKey)):
        return type(pub).__name__.replace("PublicKey", ""), "25519"
    name = type(pub).__name__
    if "MLDSA" in name or "MLKEM" in name or "SLH" in name:
        return name.replace("PublicKey", ""), "pqc"
    return name, None


def analyse_cert(cert, where):
    out = []
    alg, adv = key_info(cert.public_key())
    try:
        exp = cert.not_valid_after_utc
    except AttributeError:
        exp = cert.not_valid_after
    subject = cert.subject.rfc4514_string()[:80]
    risk = "GOOD" if adv == "pqc" else ("CRITICAL" if adv else "MEDIUM")
    out.append(dict(risk=risk, finding=f"Certificate: {alg}", category="certificate", location=where,
                    detail=f"subject={subject}; expires={exp:%Y-%m-%d}; sig={getattr(cert.signature_hash_algorithm, 'name', '?')}",
                    advice=ADVICE.get(adv, "")))
    h = getattr(cert.signature_hash_algorithm, "name", "")
    if h in ("md5", "sha1"):
        out.append(dict(risk="MEDIUM", finding=f"Certificate signed with {h.upper()}", category="certificate",
                        location=where, detail=subject, advice=ADVICE["hash"]))
    return out


def analyse_pem_blocks(data: bytes, where):
    out = []
    for m in PEM_BLOCK.finditer(data):
        kind, blob = m.group(1).decode(), m.group(0)
        try:
            if kind == "CERTIFICATE":
                out += analyse_cert(x509.load_pem_x509_certificate(blob), where)
            elif kind == "PUBLIC KEY":
                alg, adv = key_info(serialization.load_pem_public_key(blob))
                if adv:
                    out.append(dict(risk="GOOD" if adv == "pqc" else "HIGH", finding=f"Public key: {alg}",
                                    category="key-material", location=where, detail="", advice=ADVICE[adv]))
            elif kind in ("PRIVATE KEY", "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"):
                try:
                    k = (serialization.load_ssh_private_key(blob, None) if "OPENSSH" in kind
                         else serialization.load_pem_private_key(blob, None))
                    alg, adv = key_info(k.public_key())
                except TypeError:   # password protected
                    alg, adv = "encrypted private key (type hidden)", "rsa"
                if adv:
                    out.append(dict(risk="GOOD" if adv == "pqc" else "CRITICAL", finding=f"Private key: {alg}",
                                    category="key-material", location=where,
                                    detail="Private key stored in file - also check it should be here at all",
                                    advice=ADVICE[adv]))
            elif kind == "ENCRYPTED PRIVATE KEY":
                out.append(dict(risk="CRITICAL", finding="Encrypted private key (algorithm unknown)", category="key-material",
                                location=where, detail="Decrypt to identify; likely RSA/ECC", advice=ADVICE["rsa"]))
        except Exception as e:
            out.append(dict(risk="MEDIUM", finding=f"Unparseable PEM block: {kind}", category="key-material",
                            location=where, detail=str(e)[:80], advice="Review manually"))
    return out


def scan_file(path, root):
    rel = os.path.relpath(path, root)
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return []
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    ext = os.path.splitext(path)[1].lower()
    findings = []
    if ext in (".der", ".cer", ".crt") and not data.lstrip().startswith(b"-----"):
        try:
            return analyse_cert(x509.load_der_x509_certificate(data), rel)
        except Exception:
            pass
    if b"\x00" in data[:8192]:
        return []   # binary
    if b"-----BEGIN" in data:
        findings += analyse_pem_blocks(data, rel)
    text = data.decode("utf-8", "replace")
    parsed_pem = bool(findings)
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for name, rx, risk, cat, adv in COMPILED:
            if cat == "key-material" and parsed_pem:
                continue
            m = rx.search(line)
            if m:
                findings.append(dict(risk=risk, finding=name, category=cat, location=f"{rel}:{lineno}",
                                     detail=line.strip()[:120], advice=ADVICE[adv]))
    return findings


def scan_path(root):
    root = os.path.abspath(root)
    findings, files = [], 0
    if os.path.isfile(root):
        return scan_file(root, os.path.dirname(root)), 1
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            files += 1
            findings += scan_file(os.path.join(dirpath, fn), root)
    return findings, files


def scan_tls(host, port=443):
    """Check a live server: TLS version, cipher and certificate key type."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
            version, cipher = t.version(), t.cipher()[0]
            group = t.group() if hasattr(t, "group") else None   # Python 3.13+/OpenSSL 3.5
    where = f"{host}:{port}"
    out = analyse_cert(x509.load_der_x509_certificate(der), where)
    out.append(dict(risk="MEDIUM" if version in ("TLSv1", "TLSv1.1") else "GOOD", finding=f"TLS version {version}",
                    category="tls", location=where, detail=f"cipher={cipher}",
                    advice=ADVICE["tls"] if version != "TLSv1.3" else "TLS 1.3 in use."))
    if group:
        pq = "MLKEM" in group.upper() or "KYBER" in group.upper()
        out.append(dict(risk="GOOD" if pq else "HIGH", finding=f"Key exchange group {group}", category="tls",
                        location=where, detail="", advice=ADVICE["pqc"] if pq else ADVICE["25519"]))
    else:
        out.append(dict(risk="HIGH", finding="Key exchange group not visible from this Python/OpenSSL",
                        category="tls", location=where,
                        detail="Assume classical ECDHE unless server confirms X25519MLKEM768",
                        advice="Enable X25519MLKEM768 on the server/load balancer (OpenSSL 3.5+, recent nginx/Cloudflare/AWS)."))
    return out


def summarise(findings):
    counts = {k: 0 for k in RISK_ORDER}
    for f in findings:
        counts[f["risk"]] += 1
    vulnerable = counts["CRITICAL"] + counts["HIGH"]
    score = max(0, 100 - counts["CRITICAL"] * 10 - counts["HIGH"] * 3 - counts["MEDIUM"])
    return counts, vulnerable, score


def write_reports(findings, target, files, out_prefix):
    findings.sort(key=lambda f: (RISK_ORDER[f["risk"]], f["location"]))
    counts, vulnerable, score = summarise(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(out_prefix + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["risk", "finding", "category", "location", "detail", "advice"])
        w.writeheader(); w.writerows(findings)
    inventory = {"tool": "QSafe scanner", "generated": now, "target": target, "files_scanned": files,
                 "summary": counts, "quantum_readiness_score": score, "assets": findings}
    with open(out_prefix + ".json", "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    L = [f"# Quantum-Readiness Report", "", f"- **Target:** `{target}`", f"- **Scanned:** {now} ({files} files)",
         f"- **Quantum-readiness score:** {score}/100", "",
         "| Risk | Count | Meaning |", "|---|---|---|",
         f"| CRITICAL | {counts['CRITICAL']} | Keys/certificates breakable by a quantum computer (Shor) |",
         f"| HIGH | {counts['HIGH']} | Code/config using RSA, ECC, DH, X25519/Ed25519 |",
         f"| MEDIUM | {counts['MEDIUM']} | Weak or quantum-weakened crypto (MD5, SHA-1, AES-128, old TLS) |",
         f"| GOOD | {counts['GOOD']} | Post-quantum crypto already present |", "",
         "## Recommended migration order",
         "1. **Long-lived secrets & key exchange** (TLS, VPN, file/database encryption) - exposed to *harvest now, decrypt later* today. Move to hybrid ML-KEM.",
         "2. **Long-lived signatures** (root/intermediate CAs, firmware and code signing). Plan ML-DSA / SLH-DSA.",
         "3. **Short-lived signatures and auth** (JWT, SSH user keys) once libraries and platforms support PQC.",
         "4. **Clean-up**: remove MD5/SHA-1/3DES/RC4, move to AES-256 and SHA-384+.",
         "5. **Crypto-agility**: centralise crypto config so algorithms can be swapped without code rewrites.", "",
         "## Findings", "", "| Risk | Finding | Location | Detail |", "|---|---|---|---|"]
    for f in findings:
        d = f["detail"].replace("|", "\\|").replace("`", "'")
        L.append(f"| {f['risk']} | {f['finding']} | `{f['location']}` | {d} |")
    L += ["", "## Advice by finding type", ""]
    for name in sorted({(f["finding"], f["advice"]) for f in findings if f["advice"]}):
        L.append(f"- **{name[0]}** - {name[1]}")
    with open(out_prefix + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return counts, vulnerable, score
