import unittest
import os

from core import crypto


class TestCrypto(unittest.TestCase):
    def test_aead_roundtrip(self):
        key = os.urandom(32)
        msg = b"hello sealed bid"
        aad = b"auction|bid|aad"
        blob = crypto.aead_encrypt(key, msg, aad)
        out = crypto.aead_decrypt(key, blob, aad)
        self.assertEqual(out, msg)

    def test_sign_verify(self):
        sk, pk = crypto.gen_ecdsa_keypair()
        msg = b"important message"
        sig = crypto.sign(sk, msg)
        self.assertTrue(crypto.verify(pk, msg, sig))
        self.assertFalse(crypto.verify(pk, msg + b"x", sig))

    def test_sealed_box(self):
        r_sk, r_pk = crypto.gen_ecdsa_keypair()
        msg = b"share payload"
        aad = b"auction|bid|authority"
        sealed = crypto.seal_to_public(r_pk, msg, aad=aad)
        out = crypto.open_with_private(r_sk, sealed, aad=aad)
        self.assertEqual(out, msg)


if __name__ == "__main__":
    unittest.main()
