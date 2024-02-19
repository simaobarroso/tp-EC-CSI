from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import unittest
from cryptography.hazmat.primitives import serialization


class PrivateChannel:
    def __init__(self):
        self.private_key = x448.X448PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def exchange_keys(self, peer_public_key):
        shared_key = self.private_key.exchange(x448.X448PublicKey.from_public_bytes(peer_public_key))
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key

    def sign_data(self, data):
        private_key_ed448 = ed448.Ed448PrivateKey.generate()
        signature = private_key_ed448.sign(data)
        return signature

    def verify_signature(self, signature, data, peer_public_key):
        public_key_ed448 = ed448.Ed448PublicKey.from_public_bytes(peer_public_key)
        public_key_ed448.verify(signature, data)


class TestPrivateChannel(unittest.TestCase):
    def setUp(self):
        self.channel1 = PrivateChannel()
        self.channel2 = PrivateChannel()

    def test_key_exchange(self):
        # Test that key exchange produces the same key on both channels
        key1 = self.channel1.exchange_keys(self.channel2.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        key2 = self.channel2.exchange_keys(self.channel1.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        self.assertEqual(key1, key2)

    def test_sign_and_verify(self):
        # Test that data signed by one channel can be verified by the other
        data = b"test data"
        signature = self.channel1.sign_data(data)
        self.channel2.verify_signature(signature, data, self.channel1.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

if __name__ == '__main__':
    unittest.main()