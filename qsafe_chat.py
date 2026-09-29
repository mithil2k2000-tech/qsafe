"""
QSafe secure chat: quantum-safe encrypted messaging over TCP.

Handshake (1 round trip):
  Client -> Server : fresh ML-KEM-768 public key + fresh X25519 public key + random nonce
  Server -> Client : ML-KEM ciphertext + fresh X25519 public key + nonce
                     + hybrid signature (ML-DSA-65 + Ed25519) over the whole transcript,
                       made with the server's long-term identity key
  Client verifies the signature against the server's PINNED public key file,
  so a man-in-the-middle cannot impersonate the server.

Both sides derive two AES-256-GCM keys (one per direction) from
ML-KEM secret + X25519 secret + transcript hash. All handshake keys are
ephemeral -> forward secrecy: stealing the server key later does not
decrypt recorded conversations ("harvest now, decrypt later" is blocked).
Messages use strict counters so replayed, reordered or dropped messages are rejected.
"""
import hashlib, json, os, socket, struct, sys, threading
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from qsafe_core import Identity, PublicIdentity, QSafeError, b64e, b64d

MAX_FRAME = 1_000_000


def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("Connection closed")
        buf += part
    return buf


def recv_frame(sock) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise QSafeError("Frame too large")
    return recv_exact(sock, n)


class SecureChannel:
    def __init__(self, sock, send_key, recv_key, peer_name, session_id):
        self.sock = sock
        self._send, self._recv = AESGCM(send_key), AESGCM(recv_key)
        self._send_ctr = self._recv_ctr = 0
        self._lock = threading.Lock()
        self.peer_name, self.session_id = peer_name, session_id

    def send(self, data: bytes):
        with self._lock:
            nonce = b"\x00\x00\x00\x00" + struct.pack(">Q", self._send_ctr)
            self._send_ctr += 1
            send_frame(self.sock, self._send.encrypt(nonce, data, b"qsafe-chat-msg"))

    def recv(self) -> bytes:
        ct = recv_frame(self.sock)
        nonce = b"\x00\x00\x00\x00" + struct.pack(">Q", self._recv_ctr)
        try:
            pt = self._recv.decrypt(nonce, ct, b"qsafe-chat-msg")
        except InvalidTag:
            raise QSafeError("TAMPERED / REPLAYED message rejected - closing connection")
        self._recv_ctr += 1
        return pt

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _derive(ss_pq, ss_x, transcript_hash):
    k = HKDF(algorithm=hashes.SHA256(), length=64, salt=transcript_hash,
             info=b"qsafe-v1-chat-keys").derive(ss_pq + ss_x)
    return k[:32], k[32:]   # client->server, server->client


def client_handshake(sock, server_pub: PublicIdentity) -> SecureChannel:
    kem = mlkem.MLKEM768PrivateKey.generate()
    xk = x25519.X25519PrivateKey.generate()
    hello = json.dumps({"v": "qsafe-v1-chat", "ml_kem_pub": b64e(kem.public_key().public_bytes_raw()),
                        "x25519": b64e(xk.public_key().public_bytes_raw()),
                        "nonce": b64e(os.urandom(32))}).encode()
    send_frame(sock, hello)
    reply = json.loads(recv_frame(sock))
    body = json.dumps(reply["body"], sort_keys=True).encode()
    th = hashlib.sha256(hello + body).digest()
    server_pub.verify(b"qsafe-v1-chat-handshake:" + th, reply["sig"])   # authenticates the server
    b = reply["body"]
    ss_pq = kem.decapsulate(b64d(b["ml_kem_ct"]))
    ss_x = xk.exchange(x25519.X25519PublicKey.from_public_bytes(b64d(b["x25519"])))
    c2s, s2c = _derive(ss_pq, ss_x, th)
    return SecureChannel(sock, c2s, s2c, server_pub.name, th.hex()[:16])


def server_handshake(sock, me: Identity) -> SecureChannel:
    hello_raw = recv_frame(sock)
    hello = json.loads(hello_raw)
    if hello.get("v") != "qsafe-v1-chat":
        raise QSafeError("Unknown protocol version")
    client_kem = mlkem.MLKEM768PublicKey.from_public_bytes(b64d(hello["ml_kem_pub"]))
    ss_pq, ct = client_kem.encapsulate()
    xk = x25519.X25519PrivateKey.generate()
    ss_x = xk.exchange(x25519.X25519PublicKey.from_public_bytes(b64d(hello["x25519"])))
    body = {"ml_kem_ct": b64e(ct), "x25519": b64e(xk.public_key().public_bytes_raw()),
            "nonce": b64e(os.urandom(32)), "server": me.fingerprint()}
    th = hashlib.sha256(hello_raw + json.dumps(body, sort_keys=True).encode()).digest()
    send_frame(sock, json.dumps({"body": body, "sig": me.sign(b"qsafe-v1-chat-handshake:" + th)}).encode())
    c2s, s2c = _derive(ss_pq, ss_x, th)
    return SecureChannel(sock, s2c, c2s, "client", th.hex()[:16])


def _chat_loop(ch: SecureChannel, my_name: str):
    def reader():
        try:
            while True:
                msg = ch.recv().decode("utf-8", "replace")
                print(f"\r[{ch.peer_name}] {msg}\n> ", end="", flush=True)
        except (ConnectionError, OSError):
            print("\n[connection closed]")
        except QSafeError as e:
            print(f"\n[SECURITY] {e}")
        finally:
            ch.close()
            os._exit(0)
    threading.Thread(target=reader, daemon=True).start()
    print("Type messages and press Enter. /quit to exit.")
    try:
        while True:
            line = input("> ")
            if line.strip() == "/quit":
                break
            ch.send(f"{line}".encode())
    except (EOFError, KeyboardInterrupt):
        pass
    ch.close()


def run_server(me: Identity, host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port)); srv.listen(1)
    print(f"QSafe chat server '{me.name}' listening on {host}:{port}")
    print(f"Server fingerprint: {me.fingerprint()}")
    print("Give clients your .pub file (and have them check this fingerprint).")
    conn, addr = srv.accept()
    print(f"Connection from {addr[0]}:{addr[1]} - performing hybrid ML-KEM-768 + X25519 handshake...")
    ch = server_handshake(conn, me)
    ch.peer_name = f"client@{addr[0]}"
    print(f"Secure session established (session id {ch.session_id}). Cipher: AES-256-GCM")
    _chat_loop(ch, me.name)


def run_client(server_pub: PublicIdentity, host, port):
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(None)
    print(f"Connecting to {host}:{port}, expecting server '{server_pub.name}' {server_pub.fingerprint()}")
    ch = client_handshake(sock, server_pub)
    print(f"Server identity VERIFIED (ML-DSA-65 + Ed25519). Session id {ch.session_id}. Cipher: AES-256-GCM")
    _chat_loop(ch, "me")
