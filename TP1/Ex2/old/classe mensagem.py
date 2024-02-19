from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from os import urandom

"""
class MyClass:
    def __init__(self, arg1, arg2):
        self.attribute1 = arg1
        self.attribute2 = arg2


obj = MyClass("value1", "value2")

        if mode == 1:
            cypher = ChaCha20Poly1305(key)
        else:
            #cypher = ChaCha20Poly1305(key)
            print("Não definido para o AES ainda!")

"""
class message():
    def __init__(self, key,mode):
        key = key
        mode = mode

    
    def cifra(self):
        tweak = urandom(12)
        if mode == 1:
        return ()