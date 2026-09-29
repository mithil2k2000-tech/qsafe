#!/usr/bin/env python3
"""
QSafe - quantum-safe security toolkit.

  python qsafe.py keygen alice                      create alice.key (private) + alice.pub (share this)
  python qsafe.py fingerprint alice.pub             show a key's fingerprint (compare out loud / by phone)
  python qsafe.py encrypt report.pdf -r bob.pub [-r alice.pub] [--sign alice.key]
  python qsafe.py decrypt report.pdf.qsafe -k bob.key [--from alice.pub]
  python qsafe.py sign contract.pdf -k alice.key    -> contract.pdf.qsig
  python qsafe.py verify contract.pdf --from alice.pub
  python qsafe.py chat-server -k server.key [--port 5050]
  python qsafe.py chat-client --server-pub server.pub --host 192.168.1.20 [--port 5050]
  python qsafe.py scan C:\\path\\to\\project [--tls example.com] [--out report]
  python qsafe.py selftest

Password for private keys is asked interactively (or set QSAFE_PASSWORD for automation).
"""
import argparse, getpass, os, sys, time


def need_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa  # noqa
    except ImportError:
        sys.exit("This needs a recent 'cryptography' package with ML-KEM/ML-DSA support.\n"
                 "Run:  pip install -U -r requirements.txt")


need_crypto()
from qsafe_core import (Identity, PublicIdentity, QSafeError, encrypt_file, decrypt_file,
                        read_header, sign_file, verify_file)


def ask_password(confirm=False, label="key"):
    env = os.environ.get("QSAFE_PASSWORD")
    if env:
        return env
    pw = getpass.getpass(f"Password for {label}: ")
    if confirm:
        if len(pw) < 10:
            sys.exit("Use at least 10 characters (a passphrase of 3-4 random words is ideal).")
        if getpass.getpass("Repeat password: ") != pw:
            sys.exit("Passwords do not match.")
    return pw


def load_private(path):
    return Identity.load(path, ask_password(label=os.path.basename(path)))


def cmd_keygen(a):
    key, pub = a.name + ".key", a.name + ".pub"
    if os.path.exists(key) and not a.force:
        sys.exit(f"{key} already exists (use --force to overwrite)")
    ident = Identity.generate(a.name)
    ident.save(key, ask_password(confirm=True, label=f"new key '{a.name}'"))
    ident.public().save(pub)
    print(f"Created {key}  (PRIVATE - keep secret, password protected)")
    print(f"Created {pub}  (public - share with others)")
    print(f"Fingerprint: {ident.fingerprint()}")
    print("Algorithms: ML-KEM-768 + X25519 (encryption), ML-DSA-65 + Ed25519 (signatures)")


def cmd_fingerprint(a):
    p = PublicIdentity.load(a.pub)
    print(f"{p.name}: {p.fingerprint()}")


def cmd_encrypt(a):
    recips = [PublicIdentity.load(r) for r in a.recipient]
    signer = load_private(a.sign) if a.sign else None
    out = a.out or a.file + ".qsafe"
    t = time.time()
    encrypt_file(a.file, out, recips, signer)
    print(f"Encrypted -> {out}  ({time.time() - t:.2f}s)")
    print("For: " + ", ".join(f"{r.name} ({r.fingerprint()})" for r in recips))
    if signer:
        print(f"Signed by: {signer.name} ({signer.fingerprint()})")
    if a.delete_original:
        os.remove(a.file); print(f"Deleted original {a.file}")


def cmd_decrypt(a):
    me = load_private(a.key)
    sender = PublicIdentity.load(a.sender) if a.sender else None
    out = a.out or (a.file[:-6] if a.file.endswith(".qsafe") else a.file + ".decrypted")
    if os.path.exists(out) and not a.force:
        sys.exit(f"{out} already exists (use -o or --force)")
    _, status = decrypt_file(a.file, out, me, sender)
    print(f"Decrypted -> {out}")
    print(f"Integrity: OK (AES-256-GCM authenticated)   Signature: {status}")


def cmd_info(a):
    h = read_header(a.file)
    print(f"Cipher: {h['cipher']}   Signed by: {h.get('signed_by') or 'nobody'}")
    for r in h["recipients"]:
        print(f"  recipient {r['name']}  {r['to']}")


def cmd_sign(a):
    me = load_private(a.key)
    out = a.out or a.file + ".qsig"
    sign_file(a.file, me, out)
    print(f"Signature written -> {out}  (ML-DSA-65 + Ed25519, signer {me.fingerprint()})")


def cmd_verify(a):
    sig = a.sig or a.file + ".qsig"
    signer = PublicIdentity.load(a.sender)
    verify_file(a.file, sig, signer)
    print(f"VALID signature by {signer.name} ({signer.fingerprint()}) - file unchanged since signing")


def cmd_chat_server(a):
    from qsafe_chat import run_server
    run_server(load_private(a.key), a.host, a.port)


def cmd_chat_client(a):
    from qsafe_chat import run_client
    run_client(PublicIdentity.load(a.server_pub), a.host, a.port)


def cmd_scan(a):
    from qsafe_scan import scan_path, scan_tls, write_reports
    findings, files, targets = [], 0, []
    for p in a.paths:
        f, n = scan_path(p); findings += f; files += n; targets.append(p)
    for host in a.tls or []:
        h, _, port = host.partition(":")
        try:
            findings += scan_tls(h, int(port or 443)); targets.append(f"tls://{host}")
        except Exception as e:
            print(f"TLS check of {host} failed: {e}")
    counts, vulnerable, score = write_reports(findings, ", ".join(targets), files, a.out)
    print(f"Scanned {files} files" + (f" and {len(a.tls)} server(s)" if a.tls else ""))
    print(f"  CRITICAL {counts['CRITICAL']}   HIGH {counts['HIGH']}   MEDIUM {counts['MEDIUM']}   GOOD {counts['GOOD']}")
    print(f"  Quantum-readiness score: {score}/100")
    print(f"Reports: {a.out}.md  {a.out}.csv  {a.out}.json")


def cmd_selftest(a):
    import tempfile
    from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
    print("Running self-test...")
    t = time.time(); k = mlkem.MLKEM768PrivateKey.generate(); ss, ct = k.public_key().encapsulate()
    assert k.decapsulate(ct) == ss
    print(f"  ML-KEM-768  OK  public key {len(k.public_key().public_bytes_raw())} B, ciphertext {len(ct)} B")
    s = mldsa.MLDSA65PrivateKey.generate(); sig = s.sign(b"x"); s.public_key().verify(sig, b"x")
    print(f"  ML-DSA-65   OK  public key {len(s.public_key().public_bytes_raw())} B, signature {len(sig)} B")
    with tempfile.TemporaryDirectory() as d:
        alice = Identity.generate("alice"); bob = Identity.generate("bob")
        src = os.path.join(d, "m.txt"); open(src, "wb").write(os.urandom(3_000_000))
        encrypt_file(src, src + ".qsafe", [bob.public()], alice)
        decrypt_file(src + ".qsafe", src + ".out", bob, alice.public())
        assert open(src, "rb").read() == open(src + ".out", "rb").read()
    print(f"  Hybrid file encrypt/sign/decrypt/verify OK ({time.time() - t:.2f}s)")
    print("All good - post-quantum crypto is working on this machine.")


def main():
    p = argparse.ArgumentParser(prog="qsafe", description="Quantum-safe security toolkit",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sp = p.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("keygen", help="create a key pair"); s.add_argument("name"); s.add_argument("--force", action="store_true"); s.set_defaults(f=cmd_keygen)
    s = sp.add_parser("fingerprint", help="show fingerprint of a .pub"); s.add_argument("pub"); s.set_defaults(f=cmd_fingerprint)
    s = sp.add_parser("encrypt", help="encrypt a file"); s.add_argument("file")
    s.add_argument("-r", "--recipient", action="append", required=True, help="recipient .pub (repeatable)")
    s.add_argument("--sign", metavar="KEY", help="also sign with your .key"); s.add_argument("-o", "--out")
    s.add_argument("--delete-original", action="store_true"); s.set_defaults(f=cmd_encrypt)
    s = sp.add_parser("decrypt", help="decrypt a file"); s.add_argument("file"); s.add_argument("-k", "--key", required=True)
    s.add_argument("--from", dest="sender", help="require signature from this .pub"); s.add_argument("-o", "--out")
    s.add_argument("--force", action="store_true"); s.set_defaults(f=cmd_decrypt)
    s = sp.add_parser("info", help="show who an encrypted file is for"); s.add_argument("file"); s.set_defaults(f=cmd_info)
    s = sp.add_parser("sign", help="detached signature"); s.add_argument("file"); s.add_argument("-k", "--key", required=True)
    s.add_argument("-o", "--out"); s.set_defaults(f=cmd_sign)
    s = sp.add_parser("verify", help="verify detached signature"); s.add_argument("file")
    s.add_argument("--from", dest="sender", required=True); s.add_argument("--sig"); s.set_defaults(f=cmd_verify)
    s = sp.add_parser("chat-server", help="start secure chat server"); s.add_argument("-k", "--key", required=True)
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=5050); s.set_defaults(f=cmd_chat_server)
    s = sp.add_parser("chat-client", help="connect to secure chat"); s.add_argument("--server-pub", required=True)
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=5050); s.set_defaults(f=cmd_chat_client)
    s = sp.add_parser("scan", help="find quantum-vulnerable crypto"); s.add_argument("paths", nargs="*", default=[])
    s.add_argument("--tls", action="append", help="also check a live server host[:port]")
    s.add_argument("--out", default="quantum_readiness_report"); s.set_defaults(f=cmd_scan)
    s = sp.add_parser("selftest", help="check everything works"); s.set_defaults(f=cmd_selftest)
    a = p.parse_args()
    try:
        a.f(a)
    except QSafeError as e:
        sys.exit(f"ERROR: {e}")
    except FileNotFoundError as e:
        sys.exit(f"ERROR: file not found: {e.filename}")


if __name__ == "__main__":
    main()
