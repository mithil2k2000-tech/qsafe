"""Creates demo_vulnerable_app/ - a fake company project full of quantum-vulnerable
crypto, so you can try the scanner. (All keys are throwaway demo keys.)"""
import datetime, os


def _save(path, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

D = "demo_vulnerable_app"
os.makedirs(f"{D}/certs", exist_ok=True); os.makedirs(f"{D}/src", exist_ok=True); os.makedirs(f"{D}/config", exist_ok=True)
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shop.example-demo.local")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825)).sign(k, hashes.SHA256()))
_save(f"{D}/certs/server.crt", cert.public_bytes(serialization.Encoding.PEM))
_save(f"{D}/certs/server.key", k.private_bytes(serialization.Encoding.PEM,
     serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
e = ec.generate_private_key(ec.SECP256R1())
_save(f"{D}/certs/signing_ec.key", e.private_bytes(serialization.Encoding.PEM,
     serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
_save(f"{D}/src/auth.py", '''import hashlib, jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def make_token(user, private_key):
    return jwt.encode({"sub": user}, private_key, algorithm="RS256")

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()   # weak!

def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
''')
_save(f"{D}/src/payments.js", '''const crypto = require("crypto");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const ecdh = crypto.createECDH("secp256k1");   // ECDH key agreement
const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
''')
_save(f"{D}/config/nginx.conf", '''server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/server.crt;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:DES-CBC3-SHA;
    ssl_dhparam         /etc/ssl/dhparam.pem;
}
''')
_save(f"{D}/config/authorized_keys", 
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdemo admin@laptop\n"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIdemo dev@workstation\n")
_save(f"{D}/src/new_vpn.py", '''# migrated module - uses hybrid post-quantum key exchange
from cryptography.hazmat.primitives.asymmetric import mlkem
KEX = "X25519MLKEM768"
kem = mlkem.MLKEM768PrivateKey.generate()
''')
print(f"Created {D}/ - now run:  python qsafe.py scan {D}")
