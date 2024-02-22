
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_tweaks(number_of_blocks, plaintext_length, nonce):
    cipher_tweaks = []
    # cipher tweaks [nonce|counter|0]
    for i in range(0, number_of_blocks):
        tweak = nonce + int(i).to_bytes(16, byteorder='big')
        tweak = int.from_bytes(tweak, byteorder='big')

        # remove last bit and add the final bit 0
        tweak = tweak >> 1
        tweak = tweak << 1

        tweak = tweak.to_bytes(32, byteorder='big')
        cipher_tweaks.append(tweak)
    
    # authentication tweak [nonce|plaintext_length|0]
    auth_tweak = nonce + plaintext_length.to_bytes(16, byteorder='big')
    auth_tweak = int.from_bytes(auth_tweak, byteorder='big')

    # last bit of auth_tweak to 1
    mask = 0b1
    auth_tweak = auth_tweak | mask
    auth_tweak = auth_tweak.to_bytes(32, byteorder='big')

    return cipher_tweaks, auth_tweak


def decrypt(ciphertext, tag, nonce, nonce_tweak, cipher_key, ad):
    # divide plaintext into blocks
    blocks = [ciphertext[i:i+32] for i in range(0, len(ciphertext), 32)]

    number_of_blocks = len(blocks)
    n = len(ciphertext)
    r = len(tag)
    length = n - (32 - r)

    # generate tweaks
    cipher_tweaks, auth_tweak = generate_tweaks(number_of_blocks, length, nonce_tweak)

    decrypted_blocks = []

    # decrypt blocks
    for w in range(0, number_of_blocks):
        plaintext = get_ciphertext(cipher_key, nonce, cipher_tweaks[w], blocks[w], ad)
        decrypted_blocks.append(plaintext)
    
    # authentication phase
    auth = decrypted_blocks[0]
    for i in range(1, number_of_blocks):
        xored = [(a^b).to_bytes(1,byteorder='big') for (a,b) in zip(auth, decrypted_blocks[i])]
        auth = b"".join(xored)

    generated_tag = get_ciphertext(cipher_key, nonce, auth_tweak, auth, ad)[:r]

    # verify authentication
    if tag == generated_tag:
        decrypted_blocks[number_of_blocks - 1] = decrypted_blocks[number_of_blocks - 1][:r]
        plaintext = b"".join(decrypted_blocks)

    else :
        return "ERROR! Different tag used in authentication."
        
    return plaintext.decode('utf-8')

def get_ciphertext(cipher_key, nonce, tweak, plaintext, ad):

    chacha = ChaCha20Poly1305(cipher_key)
    ciphertext = chacha.encrypt(nonce, plaintext, ad)

    xored = bytes([(a^b) for (a,b) in zip(tweak, ciphertext)])

    return xored

def encrypt(plaintext, cipher_key, ad):
    # divide plaintext into blocks
    blocks = []
    for i in range(0, len(plaintext), 32):
        block = plaintext[i:i+32].encode('utf-8')
        # padding
        r = len(block)
        if r < 32:
            blocks.append(block.ljust(32, b'\0'))
        else:
            blocks.append(block)
    
    length = len(plaintext)
    number_of_blocks = len(blocks)

    # generate tweaks
    nonce_tweak = os.urandom(16)
    cipher_tweaks, auth_tweak = generate_tweaks(number_of_blocks, length, nonce_tweak)

    encrypted_blocks = []

    nonce = os.urandom(12)
    
    # encrypt first m-1 blocks
    for w in range(0, number_of_blocks - 1):
        ciphertext = get_ciphertext(cipher_key, nonce, cipher_tweaks[w], blocks[w], ad)
        encrypted_blocks.append(ciphertext)
        
    # encrypt last block
    r_in_bytes = int(r).to_bytes(32, byteorder='big')
    ct = get_ciphertext(cipher_key, nonce, cipher_tweaks[number_of_blocks-1], r_in_bytes, ad)

    xored = [(a^b).to_bytes(1,byteorder='big') for (a,b) in zip(ct, blocks[number_of_blocks-1])]
    last_ciphertext = b"".join(xored)
    
    encrypted_blocks.append(last_ciphertext)

    # authentication phase
    auth = blocks[0]
    for i in range(1, number_of_blocks):
        xored = [(a^b).to_bytes(1,byteorder='big') for (a,b) in zip(auth, blocks[i])]
        auth = b"".join(xored)

    tag = get_ciphertext(cipher_key, nonce, auth_tweak, auth, ad)[:r]

    # join all encrypted blocks
    ciphertext = b"".join(encrypted_blocks)

    return ciphertext, tag, nonce, nonce_tweak

