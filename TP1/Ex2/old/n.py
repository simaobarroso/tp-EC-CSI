from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives import hashes
from os import urandom

# Generate a random 256-bit key
key = urandom(32)

# Create a ChaCha20Poly1305 instance
chacha = ChaCha20(key)

# The nonce (number used once) should be unique for each message encrypted with the same key
nonce = urandom(12)

# The associated data that will be authenticated but not encrypted
aad = b"authenticated but not encrypted payload"

# The message to be encrypted
message = b"secret message"

# Encrypt the message
ciphertext = chacha.encrypt(nonce, message, aad)

# Decrypt the message
plaintext = chacha.decrypt(nonce, ciphertext, aad)

assert message == plaintext