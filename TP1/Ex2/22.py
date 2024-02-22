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
from aux import *

nest_asyncio.apply()



class channel:
    def __init__(self, queue):
        self.queue = queue

    async def gen_keys(self):
        
        self.priv_Ed448_key = Ed448PrivateKey.generate()
        self.pub_Ed448_key = self.priv_Ed448_key.public_key()
        
        self.priv_x448_key = X448PrivateKey.generate()
        self.pub_x448_key = self.priv_x448_key.public_key()


    async def share_keys(self):
        
        await self.queue.put(self.pub_Ed448_key)
        
        sigEd448 = self.priv_Ed448_key.sign(
            self.pub_Ed448_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        
        await self.queue.put(sigEd448)

        
        await self.queue.put(self.pub_x448_key)
        
        sigx448 = self.priv_Ed448_key.sign(
            self.pub_x448_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        
        await self.queue.put(sigx448)



    async def receive_keys(self):
        
        peer_pub_Ed448_key = await self.queue.get()
        peer_pub_Ed448_key_signature = await self.queue.get()
        
        
        peer_pub_Ed448_key.verify(peer_pub_Ed448_key_signature, peer_pub_Ed448_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.peer_verify_key = peer_pub_Ed448_key
        
        
        peer_pub_x448_key = await self.queue.get()
        peer_pub_x448_key_signature = await self.queue.get()
        
        self.peer_verify_key.verify(peer_pub_x448_key_signature, peer_pub_x448_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        
        
        shared_key = self.priv_x448_key.exchange(peer_pub_x448_key)
        derived_key = HKDF(
            algorithm = hashes.SHA256(),
            length = 32, 
            salt = b"salt",
            info = b"handshake data",
        ).derive(shared_key)
        self.agreed_key = derived_key

    async def send(self, plaintext):
        ad = str(datetime.now()).encode('utf-8')

        key = self.agreed_key
                
        print("Plaintext Sent: "+str(plaintext))

        
        ciphertext,tag,nounce,tweak = encrypt(plaintext, key, ad)
        
        
        
        print("\tCiphertext Sent: "+str(ciphertext))
        
        await self.queue.put(self.priv_Ed448_key.sign(ad))
        await self.queue.put(ad)

        await self.queue.put(self.priv_Ed448_key.sign(ciphertext))
        await self.queue.put(ciphertext)
        
        await self.queue.put(self.priv_Ed448_key.sign(tag))
        await self.queue.put(tag)
        

        await self.queue.put(self.priv_Ed448_key.sign(nounce))
        await self.queue.put(nounce)

        
        await self.queue.put(self.priv_Ed448_key.sign(tweak))
        await self.queue.put(tweak)
        


    async def receive(self):
        key = self.agreed_key

        adsig = await self.queue.get()
        ad = await self.queue.get()
        self.peer_verify_key.verify(adsig, ad)
        
        sig_ctext = await self.queue.get()
        ciphertext = await self.queue.get()
        self.peer_verify_key.verify(sig_ctext, ciphertext)

        
        sig_tag = await self.queue.get()
        tag = await self.queue.get()
        self.peer_verify_key.verify(sig_tag, tag)
        
        sig_nounce = await self.queue.get()
        nounce = await self.queue.get()
        self.peer_verify_key.verify(sig_nounce, nounce)


        
        
        sig_tweak = await self.queue.get()
        tweak = await self.queue.get()
        self.peer_verify_key.verify(sig_tweak, tweak)
        
        print("\tCiphertext Received: "+str(ciphertext))
        # decrypt(ciphertext, tag, nonce, nonce_tweak, cipher_key, ad
        plaintext = decrypt(ciphertext, tag, nounce, tweak, key, ad)
        
        
        
        print("Decrypted: "+str(plaintext)+"\n")

    async def print_agreed_key(self):
        print(self.agreed_key)


async def main():
    
    queue = asyncio.Queue()

    
    emissor = channel(queue)
    receptor = channel(queue)

    
    await emissor.gen_keys()
    await receptor.gen_keys()

    
    await emissor.share_keys()
    await receptor.receive_keys()
    await receptor.share_keys()
    await emissor.receive_keys()

    
    
    

    if (emissor.agreed_key == receptor.agreed_key):
        print("Chave acordada: " + str(emissor.agreed_key) + "\n")
    else : 
        print(f"Chave não foi acordada\nChave emissor: {str(emissor.agreed_key)}\nChave recetor: {str(receptor.agreed_key)}")
        sys.exit("Chave não foi acordada")

    
    
    await emissor.send("Brave Sir Robin ran away. Bravely ran away away. . .")
    await receptor.receive()
    await receptor.send("Spam! Spam! Spam! Spam! Spam! Spam!")
    await emissor.receive()

asyncio.run(main())


