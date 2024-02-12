import ascon
import cryptography
import asyncio

hashlength=16

# Decrypt the message according to the desired params
def decrypt(text,key, nonce, associated_data):
    try:
        out_message=ascon.decrypt(key, nonce, associated_data, text, variant="Ascon-128")
    except Exception as e:
        pass
    return out_message

# Init program
async def main():
    
    # Setup the encription vars
    key_seed=input("Seed for key > ")
    nonce_seed=input("Seed for nonce > ")
    key=ascon.hash(key_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)
    nonce=ascon.hash(nonce_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)
    associated_data=f'''test_{len(key_seed)*len(nonce_seed)}'''.encode()
    reader, writer = await asyncio.open_connection('localhost', 8888)

    while True:
        try:
            while True:
                data = await reader.read(256)
                if not data:
                    break
                try:
                    message = decrypt(data, key, nonce, associated_data)
                    print(f"[Server] {message.decode()}")
                except Exception as e:
                    print(f"Error decrypting message: {e}")
                    continue
        except asyncio.CancelledError:
            pass

asyncio.run(main())
