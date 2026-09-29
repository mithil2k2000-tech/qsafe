"""
QSafe core: hybrid post-quantum cryptography.

Key exchange : ML-KEM-768 (FIPS 203)  +  X25519      -> HKDF-SHA256 combiner
Signatures   : ML-DSA-65  (FIPS 204)  +  Ed25519     -> both must verify
Data         : AES-256-GCM, chunked, truncation-protected
Private keys : encrypted at rest with scrypt + AES-256-GCM

Why hybrid? If ML-KEM/ML-DSA ever turns out to have a flaw, the classical
algorithm still protects you today; if a quantum computer breaks X25519/Ed25519,
the post-quantum algorithm still protects you. An attacker must break BOTH.
"""
import base64, hashlib, json, os, struct
from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa, x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag, InvalidSignature

VERSION = "qsafe-v1"
SIG_CONTEXT = b"qsafe-v1-signature"


class QSafeError(Exception):
    pass


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


# --------------------------------------------------------------------------
# Identities (key pairs)
# --------------------------------------------------------------------------
class PublicIdentity:
    def __init__(self, name, kem_pub, x_pub, sig_pub, ed_pub):
        self.name = name
        self.kem_pub = kem_pub          # MLKEM768PublicKey
        self.x_pub = x_pub              # X25519PublicKey
        self.sig_pub = sig_pub          # MLDSA65PublicKey
        self.ed_pub = ed_pub            # Ed25519PublicKey

    def raw(self) -> dict:
        return {
            "ml_kem_768": self.kem_pub.public_bytes_raw(),
            "x25519": self.x_pub.public_bytes_raw(),
            "ml_dsa_65": self.sig_pub.public_bytes_raw(),
            "ed25519": self.ed_pub.public_bytes_raw(),
        }

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        for k, v in sorted(self.raw().items()):
            h.update(k.encode()); h.update(v)
        d = h.hexdigest()[:32]
        return ":".join(d[i:i + 4] for i in range(0, 32, 4))

    def to_json(self) -> str:
        data = {"format": VERSION + "-public", "name": self.name,
                "fingerprint": self.fingerprint()}
        data.update({k: b64e(v) for k, v in self.raw().items()})
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, text):
        d = json.loads(text)
        if d.get("format") != VERSION + "-public":
            raise QSafeError("Not a QSafe public key file")
        pub = cls(d["name"],
                  mlkem.MLKEM768PublicKey.from_public_bytes(b64d(d["ml_kem_768"])),
                  x25519.X25519PublicKey.from_public_bytes(b64d(d["x25519"])),
                  mldsa.MLDSA65PublicKey.from_public_bytes(b64d(d["ml_dsa_65"])),
                  ed25519.Ed25519PublicKey.from_public_bytes(b64d(d["ed25519"])))
        if d.get("fingerprint") and d["fingerprint"] != pub.fingerprint():
            raise QSafeError("Public key file is corrupted (fingerprint mismatch)")
        return pub

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    # --- hybrid signature verification ---
    def verify(self, message: bytes, sig: dict) -> None:
        if sig.get("signer") != self.fingerprint():
            raise QSafeError("Signature was made by a different key "
                             f"({sig.get('signer')}), expected {self.fingerprint()}")
        try:
            self.sig_pub.verify(b64d(sig["ml_dsa_65"]), message, SIG_CONTEXT)
            self.ed_pub.verify(b64d(sig["ed25519"]), message)
        except (InvalidSignature, KeyError, ValueError):
            raise QSafeError("INVALID SIGNATURE - data was modified or not signed by this key")


class Identity:
    def __init__(self, name, kem, x, sig, ed):
        self.name, self.kem, self.x, self.sig, self.ed = name, kem, x, sig, ed

    @classmethod
    def generate(cls, name):
        return cls(name,
                   mlkem.MLKEM768PrivateKey.generate(),
                   x25519.X25519PrivateKey.generate(),
                   mldsa.MLDSA65PrivateKey.generate(),
                   ed25519.Ed25519PrivateKey.generate())

    def public(self) -> PublicIdentity:
        return PublicIdentity(self.name, self.kem.public_key(), self.x.public_key(),
                              self.sig.public_key(), self.ed.public_key())

    def fingerprint(self):
        return self.public().fingerprint()

    # --- hybrid signing ---
    def sign(self, message: bytes) -> dict:
        return {"alg": "ML-DSA-65+Ed25519", "signer": self.fingerprint(),
                "ml_dsa_65": b64e(self.sig.sign(message, SIG_CONTEXT)),
                "ed25519": b64e(self.ed.sign(message))}

    # --- storage: private key encrypted with password ---
    def save(self, path, password: str, scrypt_n=2 ** 17):
        secrets = json.dumps({
            "ml_kem_768": b64e(self.kem.private_bytes_raw()),
            "x25519": b64e(self.x.private_bytes_raw()),
            "ml_dsa_65": b64e(self.sig.private_bytes_raw()),
            "ed25519": b64e(self.ed.private_bytes_raw()),
        }).encode()
        salt, nonce = os.urandom(16), os.urandom(12)
        key = Scrypt(salt=salt, length=32, n=scrypt_n, r=8, p=1).derive(password.encode())
        aad = (VERSION + "-private:" + self.name).encode()
        ct = AESGCM(key).encrypt(nonce, secrets, aad)
        data = {"format": VERSION + "-private", "name": self.name,
                "fingerprint": self.fingerprint(),
                "kdf": {"alg": "scrypt", "n": scrypt_n, "r": 8, "p": 1, "salt": b64e(salt)},
                "cipher": "AES-256-GCM", "nonce": b64e(nonce), "ciphertext": b64e(ct)}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    @classmethod
    def load(cls, path, password: str):
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        if d.get("format") != VERSION + "-private":
            raise QSafeError("Not a QSafe private key file")
        k = d["kdf"]
        key = Scrypt(salt=b64d(k["salt"]), length=32, n=k["n"], r=k["r"], p=k["p"]).derive(password.encode())
        try:
            s = json.loads(AESGCM(key).decrypt(b64d(d["nonce"]), b64d(d["ciphertext"]),
                                               (VERSION + "-private:" + d["name"]).encode()))
        except InvalidTag:
            raise QSafeError("Wrong password (or key file has been tampered with)")
        return cls(d["name"],
                   mlkem.MLKEM768PrivateKey.from_seed_bytes(b64d(s["ml_kem_768"])),
                   x25519.X25519PrivateKey.from_private_bytes(b64d(s["x25519"])),
                   mldsa.MLDSA65PrivateKey.from_seed_bytes(b64d(s["ml_dsa_65"])),
                   ed25519.Ed25519PrivateKey.from_private_bytes(b64d(s["ed25519"])))


# --------------------------------------------------------------------------
# Hybrid KEM: ML-KEM-768 + X25519
# --------------------------------------------------------------------------
def _combine(ss_pq, ss_x, ct_pq, eph_x_pub, recipient: PublicIdentity, label: bytes) -> bytes:
    """Both shared secrets plus the full transcript go into HKDF, so the key is
    secure as long as EITHER ML-KEM or X25519 remains unbroken."""
    ikm = (ss_pq + ss_x + hashlib.sha256(ct_pq).digest() + eph_x_pub
           + recipient.x_pub.public_bytes_raw()
           + hashlib.sha256(recipient.kem_pub.public_bytes_raw()).digest())
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(ikm)


def hybrid_encapsulate(recipient: PublicIdentity, label=b"qsafe-v1-hybrid-kem"):
    ss_pq, ct_pq = recipient.kem_pub.encapsulate()
    eph = x25519.X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    ss_x = eph.exchange(recipient.x_pub)
    return _combine(ss_pq, ss_x, ct_pq, eph_pub, recipient, label), ct_pq, eph_pub


def hybrid_decapsulate(me: Identity, ct_pq, eph_pub, label=b"qsafe-v1-hybrid-kem"):
    ss_pq = me.kem.decapsulate(ct_pq)
    ss_x = me.x.exchange(x25519.X25519PublicKey.from_public_bytes(eph_pub))
    return _combine(ss_pq, ss_x, ct_pq, eph_pub, me.public(), label)


# --------------------------------------------------------------------------
# File encryption
# --------------------------------------------------------------------------
MAGIC = b"QSAFE1\n"
CHUNK = 1024 * 1024


def encrypt_file(in_path, out_path, recipients, signer: Identity = None):
    if not recipients:
        raise QSafeError("At least one recipient is required")
    file_key = os.urandom(32)
    nonce_prefix = os.urandom(7)
    entries = []
    for r in recipients:
        kek, ct_pq, eph = hybrid_encapsulate(r)
        wn = os.urandom(12)
        wrapped = AESGCM(kek).encrypt(wn, file_key, (VERSION + "-wrap:" + r.fingerprint()).encode())
        entries.append({"to": r.fingerprint(), "name": r.name, "ml_kem_ct": b64e(ct_pq),
                        "x25519_eph": b64e(eph), "nonce": b64e(wn), "wrapped_key": b64e(wrapped)})
    header = {"format": VERSION + "-file", "cipher": "AES-256-GCM", "chunk": CHUNK,
              "nonce_prefix": b64e(nonce_prefix), "recipients": entries,
              "signed_by": signer.fingerprint() if signer else None}
    hb = json.dumps(header, sort_keys=True).encode()
    aad_base = hashlib.sha256(hb).digest()
    aes = AESGCM(file_key)
    transcript = hashlib.sha512()
    tmp = out_path + ".partial"
    with open(in_path, "rb") as fin, open(tmp, "wb") as fout:
        def w(b):
            fout.write(b); transcript.update(b)
        w(MAGIC); w(struct.pack(">I", len(hb))); w(hb)
        counter = 0
        chunk = fin.read(CHUNK)
        while True:
            nxt = fin.read(CHUNK) if len(chunk) == CHUNK else b""
            final = len(nxt) == 0
            nonce = nonce_prefix + struct.pack(">I", counter) + (b"\x01" if final else b"\x00")
            ct = aes.encrypt(nonce, chunk, aad_base)
            w(struct.pack(">I", len(ct))); w(ct)
            counter += 1
            if final:
                break
            chunk = nxt
        if signer:
            sig = json.dumps(signer.sign(b"qsafe-v1-file:" + transcript.digest())).encode()
            fout.write(struct.pack(">I", len(sig))); fout.write(sig)
    os.replace(tmp, out_path)
    return header


def read_header(path):
    with open(path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise QSafeError("Not a QSafe encrypted file")
        (n,) = struct.unpack(">I", f.read(4))
        return json.loads(f.read(n))


def decrypt_file(in_path, out_path, me: Identity, expected_sender: PublicIdentity = None):
    """Returns (header, signature_status). Plaintext only appears at out_path
    after EVERY chunk and (if present) the signature has been verified."""
    transcript = hashlib.sha512()
    tmp = out_path + ".partial"
    try:
        with open(in_path, "rb") as fin, open(tmp, "wb") as fout:
            def r(n):
                b = fin.read(n)
                if len(b) != n:
                    raise QSafeError("File is truncated or corrupted")
                transcript.update(b)
                return b
            if r(len(MAGIC)) != MAGIC:
                raise QSafeError("Not a QSafe encrypted file")
            (hl,) = struct.unpack(">I", r(4))
            if hl > 10_000_000:
                raise QSafeError("Header too large")
            hb = r(hl)
            header = json.loads(hb)
            mine = [e for e in header["recipients"] if e["to"] == me.fingerprint()]
            if not mine:
                raise QSafeError("This file was not encrypted for your key")
            e = mine[0]
            try:
                kek = hybrid_decapsulate(me, b64d(e["ml_kem_ct"]), b64d(e["x25519_eph"]))
                file_key = AESGCM(kek).decrypt(b64d(e["nonce"]), b64d(e["wrapped_key"]),
                                               (VERSION + "-wrap:" + e["to"]).encode())
            except (InvalidTag, ValueError):
                raise QSafeError("Could not unlock file key - file tampered or wrong key")
            aes = AESGCM(file_key)
            aad_base = hashlib.sha256(hb).digest()
            prefix = b64d(header["nonce_prefix"])
            counter = 0
            while True:
                (cl,) = struct.unpack(">I", r(4))
                if cl > header["chunk"] + 16:
                    raise QSafeError("Corrupted chunk length")
                ct = r(cl)
                pt = None
                for final in (b"\x00", b"\x01"):
                    try:
                        pt = aes.decrypt(prefix + struct.pack(">I", counter) + final, ct, aad_base)
                        is_final = final == b"\x01"
                        break
                    except InvalidTag:
                        continue
                if pt is None:
                    raise QSafeError("TAMPERING DETECTED - chunk %d failed authentication" % counter)
                fout.write(pt)
                counter += 1
                if is_final:
                    break
            digest = transcript.digest()
            status = "unsigned"
            if header.get("signed_by"):
                lb = fin.read(4)
                if len(lb) != 4:
                    raise QSafeError("Signature missing (file claims to be signed)")
                (sl,) = struct.unpack(">I", lb)
                sig = json.loads(fin.read(sl))
                if sig.get("signer") != header["signed_by"]:
                    raise QSafeError("Signature signer does not match header")
                if expected_sender:
                    expected_sender.verify(b"qsafe-v1-file:" + digest, sig)
                    status = f"verified: signed by {expected_sender.name} ({expected_sender.fingerprint()})"
                else:
                    status = f"signed by {header['signed_by']} - NOT verified (use --from sender.pub)"
            elif expected_sender:
                raise QSafeError("You required a signature (--from) but the file is not signed")
            if fin.read(1):
                raise QSafeError("Unexpected trailing data after end of file")
        os.replace(tmp, out_path)
        return header, status
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


# --------------------------------------------------------------------------
# Detached file signatures
# --------------------------------------------------------------------------
def _file_digest(path):
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
    return h.digest()


def sign_file(path, signer: Identity, sig_path):
    d = _file_digest(path)
    sig = signer.sign(b"qsafe-v1-detached:" + d)
    sig.update({"format": VERSION + "-signature", "signer_name": signer.name,
                "sha512": d.hex(), "file": os.path.basename(path)})
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(sig, f, indent=2)
    return sig


def verify_file(path, sig_path, signer: PublicIdentity):
    with open(sig_path, "r", encoding="utf-8") as f:
        sig = json.load(f)
    d = _file_digest(path)
    signer.verify(b"qsafe-v1-detached:" + d, sig)
    return sig
