import os
import asyncio
import nest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import datetime


nest_asyncio.apply()

#SERÁ PRECISO ISTO?
def xoring(b1, b2): # use xor for multiples bytes
    if len(b1) < len(b2):
        b1 += b"\x00" * (len(b2) - len(b1))
    elif len(b2) < len(b1):
        b2 += b"\x00" * (len(b1) - len(b2))
    result = b''
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result

class Person:
    ad = str(datetime.now()).encode('utf-8')

    def __init__(self, queue):
        self.queue = queue

    async def cipher_key(self):
        # chaves privadas e publicas do Ed448
        self.cipher_E_key = Ed448PrivateKey.generate()
        self.public_cipher_E_key = self.cipher_E_key.public_key()
        # chaves privadas e publicas do X448
        self.cipher_X_key = X448PrivateKey.generate()
        self.public_cipher_X_key = self.cipher_X_key.public_key()


    async def share_cipher_key(self):
        # enviar a chave publica do Ed448
        await self.queue.put(self.public_cipher_E_key)
        # autenticar a chave publica do Ed448
        signature_E = self.cipher_E_key.sign(
            self.public_cipher_E_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        # enviar a assinatura da chave publica do Ed448
        await self.queue.put(signature_E)

        # enviar a chave publica do X448
        await self.queue.put(self.public_cipher_X_key)
        # autenticar a chave publica do X448
        signature_X = self.cipher_E_key.sign(
            self.public_cipher_X_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        # enviar a assinatura da chave publica do X448
        await self.queue.put(signature_X)



    async def receive_cipher_key(self):
        # receber chave publica do Ed448 do outro lado e a sua respetiva assinatura
        peer_cipher_E_key = await self.queue.get()
        peer_cipher_E_key_signature = await self.queue.get()
        
        # verificar a assinatura da chave publica do Ed448  do outro lado e guardar a para futuras verificações
        peer_cipher_E_key.verify(peer_cipher_E_key_signature, peer_cipher_E_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.peer_verify_key = peer_cipher_E_key
        
        # receber chave publica do X448 do outro lado e a sua respetiva assinatura
        peer_cipher_X_key = await self.queue.get()
        peer_cipher_X_key_signature = await self.queue.get()
        # verificar a assinatura da chave publica do X448
        self.peer_verify_key.verify(peer_cipher_X_key_signature, peer_cipher_X_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        
        # derivar as duas chaves publicas do X448 para obter a chave de cifra acordada entre os dois lados
        shared_key = self.cipher_X_key.exchange(peer_cipher_X_key)
        derived_key = HKDF(
            algorithm = hashes.SHA256(),
            length = 32, # 32*8=256 bits necessarios para usar chave no algoritmo AES256
            salt = None,
            info = b"handshake data",
        ).derive(shared_key)
        self.agreed_cipher_key = derived_key

    async def send(self, plaintext):
        key = self.agreed_cipher_key
        # gerar o nounce e o tweak, e as respetivas assinaturas
        #nounce = os.urandom(16)
        #signature_nou = self.cipher_E_key.sign(nounce)
        tweak = os.urandom(12)
        signature_tw = self.cipher_E_key.sign(tweak)

        # cifrar o plaintext segundo a definicao do enunciado:
        # Ẽ(w,k,x) = E(k,w ⊕ E(k,x))
        chacha = ChaCha20Poly1305(key)
        aad = bytes(self.ad)
        ciphertext2 = chacha.encrypt(tweak, plaintext, aad)
        print(b"Sent: "+ciphertext2)
        #print(aad)
        # obter a assinatura da mensagem cifrada
        signature_ct = self.cipher_E_key.sign(ciphertext2)

        # enviar a mensagem cifrada, o tweak e o nounce, bem como as assinaturas
        await self.queue.put(ciphertext2)
        await self.queue.put(signature_ct)
        await self.queue.put(aad)

        #await self.queue.put(nounce)
        #await self.queue.put(signature_nou)
        await self.queue.put(tweak)
        await self.queue.put(signature_tw)


    async def receive(self):
        key = self.agreed_cipher_key

        # receber e verificar a assinatura da mensagem cifrada
        ciphertext = await self.queue.get()
        signature_ct = await self.queue.get()
        self.peer_verify_key.verify(signature_ct, ciphertext)
        print(b"Received: "+ciphertext+b"")
        aad = await self.queue.get()

        # receber e verificar a assinatura do nounce
        #nounce = await self.queue.get()
        #signature_nou = await self.queue.get()
        #self.peer_verify_key.verify(signature_nou, nounce)

        # receber e verificar a assinatura do tweak
        tweak = await self.queue.get()
        signature_tw = await self.queue.get()
        self.peer_verify_key.verify(signature_tw, tweak)

        chacha = ChaCha20Poly1305(key)
        plaintext2 = chacha.decrypt(tweak,ciphertext,aad)
        # decifrar a mensagem de maneira inversa a definida no envio
        print(b"Decrypted: "+plaintext2+b"")

    async def print_agreed_key(self):
        print(self.agreed_cipher_key)


async def main():
    #Queue para guardar mensagens
    queue = asyncio.Queue()

    #Criar emissor e receptor
    emissor = Person(queue)
    receptor = Person(queue)

    #Criar Chaves Publicas e Privadas do Ed448 e do X448
    await emissor.cipher_key()
    await receptor.cipher_key()

    #Trocar Chave de Cifra
    await emissor.share_cipher_key()
    await receptor.receive_cipher_key()
    await receptor.share_cipher_key()
    await emissor.receive_cipher_key()

    #Verificar se as chaves de cifra são iguais
    #await emissor.print_agreed_key()
    #await receptor.print_agreed_key()
    print(emissor.agreed_cipher_key == receptor.agreed_cipher_key)

    #Enviar mensagem
    await emissor.send(b"He's Not The Messiah, He's A Very Naughty Boy.")
    await receptor.receive()

asyncio.run(main())


