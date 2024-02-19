from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import unittest
import os


class TweakableAEAD:
    def __init__(self, key, tweak):
        self.key = key
        self.tweak = tweak

    def encrypt(self, nonce, data, associated_data):
        # Apply the tweak to the key
        tweaked_key = bytes(a ^ b for a, b in zip(self.key, self.tweak))

        # Use AESGCM for the AEAD
        aesgcm = AESGCM(tweaked_key)

        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, data, associated_data)

        return ciphertext

    def decrypt(self, nonce, ciphertext, associated_data):
        # Apply the tweak to the key
        tweaked_key = bytes(a ^ b for a, b in zip(self.key, self.tweak))

        # Use AESGCM for the AEAD
        aesgcm = AESGCM(tweaked_key)

        # Decrypt the data
        data = aesgcm.decrypt(nonce, ciphertext, associated_data)

        return data

class TestTweakableAEAD(unittest.TestCase):
    print("Hello")

    def setUp(self):
        self.key = os.urandom(32)  # AES-256 key
        self.tweak = os.urandom(32)  # Tweak must be the same length as the key
        self.aead = TweakableAEAD(self.key, self.tweak)

    def test_encrypt_decrypt(self):
        # Test that data encrypted by the AEAD can be decrypted to the original data
        nonce = os.urandom(12)  # AESGCM requires a 12-byte nonce
        data = b"test data"
        associated_data = b"test associated data"

        ciphertext = self.aead.encrypt(nonce, data, associated_data)
        decrypted_data = self.aead.decrypt(nonce, ciphertext, associated_data)

        self.assertEqual(data, decrypted_data)

if __name__ == '__main__':
    unittest.main()