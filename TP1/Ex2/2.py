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
import sys


nest_asyncio.apply()

def padding(b1,b2):
    lb1 = len(b1)
    lb2 = len(b2)
    if lb1 < lb2:
        b1 += b"\x00" * (lb2 - lb1)
    #elif lb1 > lb2:
    #    b2 += b"\x00" * (lb1 - lb2)
    return xor(b1, b2)

def xor(b1, b2): 
    result = b''
    result += bytes([bt1 ^ bt2 for bt1, bt2 in zip(b1,b2) ]) # for b1, b2 in zip(b1, b2):
    return result

class channel:
    def __init__(self, queue):
        self.queue = queue

    async def gen_keys(self):
        # chaves privadas e publicas do Ed448
        self.priv_Ed448_key = Ed448PrivateKey.generate()
        self.pub_Ed448_key = self.priv_Ed448_key.public_key()
        # chaves privadas e publicas do X448
        self.priv_x448_key = X448PrivateKey.generate()
        self.pub_x448_key = self.priv_x448_key.public_key()


    async def share_keys(self):
        # enviar a chave publica do Ed448
        await self.queue.put(self.pub_Ed448_key)
        # autenticar a chave publica do Ed448
        sigEd448 = self.priv_Ed448_key.sign(
            self.pub_Ed448_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        # enviar a assinatura da chave publica do Ed448
        await self.queue.put(sigEd448)

        # enviar a chave publica do X448
        await self.queue.put(self.pub_x448_key)
        # autenticar a chave publica do X448
        sigx448 = self.priv_Ed448_key.sign(
            self.pub_x448_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        # enviar a assinatura da chave publica do X448
        await self.queue.put(sigx448)



    async def receive_keys(self):
        # receber chave publica do Ed448 do outro lado e a sua respetiva assinatura
        peer_pub_Ed448_key = await self.queue.get()
        peer_pub_Ed448_key_signature = await self.queue.get()
        
        # verificar a assinatura da chave publica do Ed448  do outro lado e guardar a para futuras verificações
        peer_pub_Ed448_key.verify(peer_pub_Ed448_key_signature, peer_pub_Ed448_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.peer_verify_key = peer_pub_Ed448_key
        
        # receber chave publica do X448 do outro lado e a sua respetiva assinatura
        peer_pub_x448_key = await self.queue.get()
        peer_pub_x448_key_signature = await self.queue.get()
        # verificar a assinatura da chave publica do X448
        self.peer_verify_key.verify(peer_pub_x448_key_signature, peer_pub_x448_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        
        # derivar as duas chaves publicas do X448 para obter a chave de cifra acordada entre os dois lados
        shared_key = self.priv_x448_key.exchange(peer_pub_x448_key)
        derived_key = HKDF(
            algorithm = hashes.SHA256(),
            length = 32, # Chave de 256 bits (AES)
            salt = b"salt",
            info = b"handshake data",
        ).derive(shared_key)
        self.agreed_key = derived_key

    async def send(self, plaintext):
        ad = str(datetime.now()).encode('utf-8')

        key = self.agreed_key
        # gerar o nounce e o tweak, e as respetivas assinaturas
        nounce = os.urandom(16)
        #nc_sig = self.priv_Ed448_key.sign(nounce)
        tweak = os.urandom(8)
        #tw_sig = self.priv_Ed448_key.sign(tweak)
        print("Plaintext Sent: "+str(plaintext))

        # cifrar o plaintext segundo a definicao do enunciado:
        # Ẽ(w,k,x) = E(k,w ^ E(k,x))
        aes = Cipher(algorithms.AES256(key), modes.CTR(nounce)).encryptor() # MUDAR PARA O AES 256 !!!
        ciphertext = aes.update(plaintext)
        xored = padding(tweak, ciphertext)
        ciphertext = aes.update(xored) + aes.finalize()
        #chacha = ChaCha20Poly1305(key)
        #aad = bytes(ad)
        #ciphertext2 = chacha.encrypt(tweak, plaintext, aad)
        print("\tCiphertext Sent: "+str(ciphertext))
        #print(aad)
        # obter a assinatura da mensagem cifrada

        await self.queue.put(self.priv_Ed448_key.sign(ciphertext))
        await self.queue.put(ciphertext)
        
        #await self.queue.put(aad)

        await self.queue.put(self.priv_Ed448_key.sign(nounce))
        await self.queue.put(nounce)

        #await self.queue.put(signature_nou)
        await self.queue.put(self.priv_Ed448_key.sign(tweak))
        await self.queue.put(tweak)
        #await self.queue.put(tw_sig)


    async def receive(self):
        key = self.agreed_key

    
        # receber e verificar a assinatura da mensagem cifrada
        sig_ctext = await self.queue.get()
        ciphertext = await self.queue.get()
        self.peer_verify_key.verify(sig_ctext, ciphertext)

        # receber e verificar a assinatura do nounce
        sig_nounce = await self.queue.get()
        nounce = await self.queue.get()
        self.peer_verify_key.verify(sig_nounce, nounce)

        # receber e verificar a assinatura do tweak
        sig_tweak = await self.queue.get()
        tweak = await self.queue.get()
        self.peer_verify_key.verify(sig_tweak, tweak)
        
        print("\tCiphertext Received: "+str(ciphertext))
        #aad = await self.queue.get()

        # receber e verificar a assinatura do nounce
        #nounce = await self.queue.get()
        #signature_nou = await self.queue.get()
        #self.peer_verify_key.verify(signature_nou, nounce)

        # receber e verificar a assinatura do tweak
        #tweak = await self.queue.get()
        #signature_tw = await self.queue.get()
        #self.peer_verify_key.verify(signature_tw, tweak)

        aes = Cipher(algorithms.AES256(key), modes.CTR(nounce)).decryptor()
        plaintext = aes.update(ciphertext)
        xored = padding(tweak, plaintext)
        plaintext = aes.update(xored) + aes.finalize()

        #chacha = ChaCha20Poly1305(key)
        #plaintext2 = chacha.decrypt(tweak,ciphertext,aad)
        # decifrar a mensagem de maneira inversa a definida no envio
        print("Decrypted: "+str(plaintext)+"\n")

    async def print_agreed_key(self):
        print(self.agreed_key)


async def main():
    #Queue para guardar mensagens
    queue = asyncio.Queue()

    #Criar emissor e receptor
    emissor = channel(queue)
    receptor = channel(queue)

    #Criar Chaves Publicas e Privadas do Ed448 e do X448
    await emissor.gen_keys()
    await receptor.gen_keys()

    #Trocar Chave de Cifra
    await emissor.share_keys()
    await receptor.receive_keys()
    await receptor.share_keys()
    await emissor.receive_keys()

    #Verificar se as chaves de cifra são iguais
    #await emissor.print_agreed_key()
    #await receptor.print_agreed_key()

    if (emissor.agreed_key == receptor.agreed_key):
        print("Chave acordada: " + str(emissor.agreed_key) + "\n")
    else : 
        print(f"Chave não foi acordada\nChave emissor: {str(emissor.agreed_key)}\nChave recetor: {str(receptor.agreed_key)}")
        sys.exit("Chave não foi acordada")

    #emissor.agreed_key = b'12345678901234567890123456789012'
    #Enviar mensagem
    await emissor.send(b"Brave Sir Robin ran away. Bravely ran away away. . .")
    await receptor.receive()
    await receptor.send(b"Spam! Spam! Spam! Spam! Spam! Spam!")
    await emissor.receive()

asyncio.run(main())


