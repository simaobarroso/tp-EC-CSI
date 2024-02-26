import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

data = b"EU NaO ACREDITO NISTO"

aad = b"authenticated but unencrypted data"

key = ChaCha20Poly1305.generate_key()

chacha = ChaCha20Poly1305(key)

nonce = os.urandom(12)

ct = chacha.encrypt(nonce, data, aad)

ct2 = chacha.encrypt(nonce, ct, aad)

print(ct2)

chacha.decrypt(nonce, ct, aad)
