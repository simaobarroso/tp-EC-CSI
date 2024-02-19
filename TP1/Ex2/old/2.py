from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.asymmetric import x448, ed448
import hmac
from cryptography.hazmat.backends import default_backend

# https://chat.openai.com/c/a5a73f4c-58bf-4d4a-bfa5-c3fcbdda8e42

# ver exemplo Pedro de alguem escutar

#MAIS ESTUDAR cap 1

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

    def generate_signature(self, data):
        # Gerar uma assinatura Ed448 para autenticar a mensagem
        private_signing_key = ed448.Ed448PrivateKey.generate()
        signature = private_signing_key.sign(data)
        return signature

    def verify_signature(self, data, signature, public_key):
        # Verificar a assinatura Ed448
        public_verifying_key = ed448.Ed448PublicKey.from_public_bytes(public_key)
        try:
            public_verifying_key.verify(signature, data)
            return True
        except Exception:
            return False

    def key_exchange(self, other_public_key):
        # Realizar o acordo de chaves X448
        shared_key = self.private_key.exchange(other_public_key)
        self.shared_key = shared_key

    def confirm_key(self, other_public_key):
        # Confirmar a chave compartilhada usando autenticação
        message = b"Key confirmation message"
        signature = self.generate_signature(message)

        # Enviar a mensagem e a assinatura ao outro agente
        other_agent = SecureChannel(public_key=other_public_key)
        if other_agent.verify_signature(message, signature, self.public_key.public_bytes()):
            print("Key confirmation successful.")
        else:
            print("Key confirmation failed.")

    def tweakable_block_cipher(self, block, tweak):
        cipher = ChaCha20.new(key=self.shared_key, nonce=tweak)
        encrypted_block = cipher.encrypt(block)
        return encrypted_block

    def encrypt(self, plaintext, associated_data):
        # Gerar um nonce único para cada chamada
        nonce = get_random_bytes(8)

        # Cifrar a chave com o nonce para obter o tweak
        tweak = self.tweakable_block_cipher(self.shared_key, nonce)

        # Cifrar os dados usando o tweak
        cipher = ChaCha20.new(key=self.shared_key, nonce=nonce)
        ciphertext = cipher.encrypt(pad(plaintext, ChaCha20.block_size))

        # Calcular o MAC usando HMAC
        mac = hmac.new(self.shared_key, ciphertext + associated_data, 'sha256').digest()

        return nonce + ciphertext + mac

    def decrypt(self, ciphertext, associated_data):
        # Extrair o nonce do início do ciphertext
        nonce = ciphertext[:8]
        ciphertext = ciphertext[8:-32]
        mac = ciphertext[-32:]

        # Calcular o MAC usando HMAC
        calculated_mac = hmac.new(self.shared_key, ciphertext + associated_data, 'sha256').digest()

        # Verificar se o MAC é válido
        if mac != calculated_mac:
            raise ValueError("MAC inválido. Os dados podem ter sido modificados.")

        # Decifrar os dados usando o tweak
        cipher = ChaCha20.new(key=self.shared_key, nonce=nonce)
        plaintext = unpad(cipher.decrypt(ciphertext), ChaCha20.block_size)

        return plaintext

# Exemplo de uso
alice_channel = SecureChannel()
bob_channel = SecureChannel()

# Alice e Bob realizam o acordo de chaves
alice_channel.key_exchange(bob_channel.public_key.public_bytes())
bob_channel.key_exchange(alice_channel.public_key.public_bytes())

# Confirmação da chave
alice_channel.confirm_key(bob_channel.public_key.public_bytes())
bob_channel.confirm_key(alice_channel.public_key.public_bytes())

# Enviar mensagem de Alice para Bob
message_from_alice = b"Hello Bob!"
associated_data_alice = b"Metadata from Alice"
ciphertext_alice = alice_channel.encrypt(message_from_alice, associated_data_alice)

# Bob recebe a mensagem e decifra
plaintext_bob = bob_channel.decrypt(ciphertext_alice, associated_data_alice)
print("Bob received:", plaintext_bob.decode('utf-8'))
