from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hmac

class SecureChannel:
    def __init__(self, private_key=None, public_key=None):
        if private_key is None and public_key is None:
            # Gerar um novo par de chaves X448 se não fornecido
            self.private_key = x448.X448PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        else:
            # Usar as chaves fornecidas
            self.private_key = private_key
            self.public_key = public_key

        # Armazenar a chave acordada após o acordo
        self.shared_key = None

    def key_exchange(self, other_public_key):
        # Realizar o acordo de chaves X448
        shared_key = self.private_key.exchange(other_public_key)
        self.shared_key = shared_key

    def generate_key_from_shared_key(self):
        # Derivar uma chave apropriada a partir da chave compartilhada usando HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        derived_key = hkdf.derive(self.shared_key)
        return derived_key

    def tweakable_block_cipher(self, key, tweak, block):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        tweaked_block = bytes([a ^ b for a, b in zip(encryptor.update(tweak + block), block)])
        return tweaked_block

    def aead_encrypt(self, key, nonce, plaintext, associated_data):
        # Derivar a chave para a cifra AEAD a partir da chave compartilhada
        derived_key = self.generate_key_from_shared_key()

        # Cifrar a chave com o nonce para obter o tweak
        tweak = self.tweakable_block_cipher(derived_key, nonce, b'')

        # Cifrar os dados
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Calcular o MAC usando HMAC
        mac = hmac.new(derived_key, ciphertext + associated_data, 'sha256').digest()

        return nonce + ciphertext + mac

    def aead_decrypt(self, key, ciphertext, associated_data):
        # Extrair o nonce do início do ciphertext
        nonce = ciphertext[:16]
        ciphertext = ciphertext[16:-32]
        mac = ciphertext[-32:]

        # Derivar a chave para a cifra AEAD a partir da chave compartilhada
        derived_key = self.generate_key_from_shared_key()

        # Calcular o MAC usando HMAC
        calculated_mac = hmac.new(derived_key, ciphertext + associated_data, 'sha256').digest()

        # Verificar se o MAC é válido
        if mac != calculated_mac:
            raise ValueError("MAC inválido. Os dados podem ter sido modificados.")

        # Decifrar os dados
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

# Exemplo de uso
alice_channel = SecureChannel()
bob_channel = SecureChannel()

# Alice e Bob realizam o acordo de chaves
alice_channel.key_exchange(bob_channel.public_key.public_bytes())
bob_channel.key_exchange(alice_channel.public_key.public_bytes())

# Confirmação da chave e exemplo de uso AEAD
nonce = b'\x00' * 16
plaintext = b"Hello, world!"
associated_data = b"Additional data"

# Alice
ciphertext = alice_channel.aead_encrypt(alice_channel.shared_key, nonce, plaintext, associated_data)
print("Alice Ciphertext:", ciphertext)

# Bob
decrypted_text = bob_channel.aead_decrypt(bob_channel.shared_key, ciphertext, associated_data)
print("Bob Decrypted text:", decrypted_text.decode('utf-8'))
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hmac

class SecureChannel:
    def __init__(self, private_key=None, public_key=None):
        if private_key is None and public_key is None:
            # Gerar um novo par de chaves X448 se não fornecido
            self.private_key = x448.X448PrivateKey.generate()
            self.public_key = self.private_key.public_key()
        else:
            # Usar as chaves fornecidas
            self.private_key = private_key
            self.public_key = public_key

        # Armazenar a chave acordada após o acordo
        self.shared_key = None

    def key_exchange(self, other_public_key):
        # Realizar o acordo de chaves X448
        shared_key = self.private_key.exchange(other_public_key)
        self.shared_key = shared_key

    def generate_key_from_shared_key(self):
        # Derivar uma chave apropriada a partir da chave compartilhada usando HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        )
        derived_key = hkdf.derive(self.shared_key)
        return derived_key

    def tweakable_block_cipher(self, key, tweak, block):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        tweaked_block = bytes([a ^ b for a, b in zip(encryptor.update(tweak + block), block)])
        return tweaked_block

    def aead_encrypt(self, key, nonce, plaintext, associated_data):
        # Derivar a chave para a cifra AEAD a partir da chave compartilhada
        derived_key = self.generate_key_from_shared_key()

        # Cifrar a chave com o nonce para obter o tweak
        tweak = self.tweakable_block_cipher(derived_key, nonce, b'')

        # Cifrar os dados
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Calcular o MAC usando HMAC
        mac = hmac.new(derived_key, ciphertext + associated_data, 'sha256').digest()

        return nonce + ciphertext + mac

    def aead_decrypt(self, key, ciphertext, associated_data):
        # Extrair o nonce do início do ciphertext
        nonce = ciphertext[:16]
        ciphertext = ciphertext[16:-32]
        mac = ciphertext[-32:]

        # Derivar a chave para a cifra AEAD a partir da chave compartilhada
        derived_key = self.generate_key_from_shared_key()

        # Calcular o MAC usando HMAC
        calculated_mac = hmac.new(derived_key, ciphertext + associated_data, 'sha256').digest()

        # Verificar se o MAC é válido
        if mac != calculated_mac:
            raise ValueError("MAC inválido. Os dados podem ter sido modificados.")

        # Decifrar os dados
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

# Exemplo de uso
alice_channel = SecureChannel()
bob_channel = SecureChannel()

# Alice e Bob realizam o acordo de chaves
alice_channel.key_exchange(bob_channel.public_key.public_bytes())
bob_channel.key_exchange(alice_channel.public_key.public_bytes())

# Confirmação da chave e exemplo de uso AEAD
nonce = b'\x00' * 16
plaintext = b"Hello, world!"
associated_data = b"Additional data"

# Alice
ciphertext = alice_channel.aead_encrypt(alice_channel.shared_key, nonce, plaintext, associated_data)
print("Alice Ciphertext:", ciphertext)

# Bob
decrypted_text = bob_channel.aead_decrypt(bob_channel.shared_key, ciphertext, associated_data)
print("Bob Decrypted text:", decrypted_text.decode('utf-8'))
