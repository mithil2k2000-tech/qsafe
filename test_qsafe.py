"""Automated tests: python test_qsafe.py"""
import os, socket, tempfile, threading, unittest
from qsafe_core import Identity, PublicIdentity, QSafeError, encrypt_file, decrypt_file, sign_file, verify_file
from qsafe_chat import client_handshake, server_handshake
from qsafe_scan import scan_path


def _w(p, b):
    with open(p, "wb") as f:
        f.write(b)


def _r(p):
    with open(p, "rb") as f:
        return f.read()


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob, cls.eve = (Identity.generate(n) for n in ("alice", "bob", "eve"))

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.src = os.path.join(self.d, "secret.bin")
        self.data = os.urandom(2_500_123)   # multi-chunk
        _w(self.src, self.data)

    def p(self, n):
        return os.path.join(self.d, n)

    def test_roundtrip_signed_multi_recipient(self):
        encrypt_file(self.src, self.p("c"), [self.bob.public(), self.alice.public()], self.alice)
        for who in (self.bob, self.alice):
            out = self.p("o_" + who.name)
            _, st = decrypt_file(self.p("c"), out, who, self.alice.public())
            self.assertEqual(_r(out), self.data)
            self.assertTrue(st.startswith("verified"))

    def test_empty_file(self):
        open(self.p("e"), "wb").close()
        encrypt_file(self.p("e"), self.p("c"), [self.bob.public()])
        decrypt_file(self.p("c"), self.p("o"), self.bob)
        self.assertEqual(_r(self.p("o")), b"")

    def test_wrong_recipient(self):
        encrypt_file(self.src, self.p("c"), [self.bob.public()])
        with self.assertRaises(QSafeError):
            decrypt_file(self.p("c"), self.p("o"), self.eve)
        self.assertFalse(os.path.exists(self.p("o")))

    def test_tamper_every_region(self):
        encrypt_file(self.src, self.p("c"), [self.bob.public()], self.alice)
        blob = _r(self.p("c"))
        for pos in (10, 400, len(blob) // 2, len(blob) - 3000, len(blob) - 5):
            bad = bytearray(blob); bad[pos] ^= 1
            _w(self.p("bad"), bad)
            with self.assertRaises(Exception, msg=f"byte {pos}"):
                decrypt_file(self.p("bad"), self.p("o"), self.bob, self.alice.public())
            self.assertFalse(os.path.exists(self.p("o")), "no plaintext released on failure")

    def test_truncation(self):
        encrypt_file(self.src, self.p("c"), [self.bob.public()])
        blob = _r(self.p("c"))
        # cut after the first full chunk
        _w(self.p("t"), blob[:len(blob) - 500_000])
        with self.assertRaises(QSafeError):
            decrypt_file(self.p("t"), self.p("o"), self.bob)

    def test_forged_sender(self):
        encrypt_file(self.src, self.p("c"), [self.bob.public()], self.eve)
        with self.assertRaises(QSafeError):
            decrypt_file(self.p("c"), self.p("o"), self.bob, self.alice.public())

    def test_unsigned_but_signature_required(self):
        encrypt_file(self.src, self.p("c"), [self.bob.public()])
        with self.assertRaises(QSafeError):
            decrypt_file(self.p("c"), self.p("o"), self.bob, self.alice.public())

    def test_detached_signature(self):
        sign_file(self.src, self.alice, self.p("s"))
        verify_file(self.src, self.p("s"), self.alice.public())
        with self.assertRaises(QSafeError):
            verify_file(self.src, self.p("s"), self.eve.public())
        _w(self.src, self.data + b"x")
        with self.assertRaises(QSafeError):
            verify_file(self.src, self.p("s"), self.alice.public())

    def test_key_storage(self):
        self.alice.save(self.p("a.key"), "correct horse battery", scrypt_n=2 ** 14)
        self.alice.public().save(self.p("a.pub"))
        again = Identity.load(self.p("a.key"), "correct horse battery")
        self.assertEqual(again.fingerprint(), self.alice.fingerprint())
        self.assertEqual(PublicIdentity.load(self.p("a.pub")).fingerprint(), self.alice.fingerprint())
        with self.assertRaises(QSafeError):
            Identity.load(self.p("a.key"), "wrong password")

    def _chat_pair(self, server_id, pinned):
        a, b = socket.socketpair()
        res = {}
        t = threading.Thread(target=lambda: res.setdefault("s", self._try(server_handshake, b, server_id)))
        t.start()
        c = self._try(client_handshake, a, pinned)
        t.join(10)
        return c, res.get("s"), a, b

    @staticmethod
    def _try(f, *args):
        try:
            return f(*args)
        except Exception as e:
            return e

    def test_chat(self):
        c, s, a, b = self._chat_pair(self.alice, self.alice.public())
        self.assertEqual(c.session_id, s.session_id)
        c.send(b"hello quantum world"); self.assertEqual(s.recv(), b"hello quantum world")
        s.send(b"hi back"); self.assertEqual(c.recv(), b"hi back")

    def test_chat_mitm_rejected(self):
        # Eve runs the server, client expects Alice -> handshake must fail
        c, s, a, b = self._chat_pair(self.eve, self.alice.public())
        self.assertIsInstance(c, QSafeError)

    def test_chat_replay_rejected(self):
        c, s, a, b = self._chat_pair(self.alice, self.alice.public())
        import qsafe_chat
        captured = []
        orig = qsafe_chat.send_frame
        qsafe_chat.send_frame = lambda sock, data: (captured.append(data), orig(sock, data))
        c.send(b"pay 10 pounds")
        qsafe_chat.send_frame = orig
        self.assertEqual(s.recv(), b"pay 10 pounds")
        orig(a, captured[0])     # attacker replays the same ciphertext
        with self.assertRaises(QSafeError):
            s.recv()

    def test_scanner(self):
        from make_demo_app import D  # creates the demo folder
        f, n = scan_path(D)
        risks = {x["risk"] for x in f}
        names = " ".join(x["finding"] for x in f)
        self.assertIn("CRITICAL", risks); self.assertIn("GOOD", risks)
        for s in ("Certificate: RSA-2048", "Private key", "JWT", "MD5", "Old TLS", "SSH Ed25519", "ECDSA", "AES-128", "Diffie"):
            self.assertIn(s, names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
