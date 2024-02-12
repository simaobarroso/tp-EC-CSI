import ascon
import cryptography
import asyncio


# Setup the encription vars
hashlength=16
key_seed=input("Seed for key > ")
nonce_seed=input("Seed for nonce > ")
key=ascon.hash(key_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)
nonce=ascon.hash(nonce_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)
associated_data=f'''test_{len(key_seed)*len(nonce_seed)}'''.encode()

# See the results of hashing with xof
print(key)
print(nonce)
print(associated_data)

# Encrypt the message according to the desired params
def encryptor(in_message,key, nonce, associated_data):
    try:
        out_message=ascon.encrypt(key, nonce, associated_data, in_message.encode(), variant="Ascon-128")
    except Exception as e:
        print(e)
    return out_message

# Handle new clients
async def handle_clients(reader, writer):

    address = writer.get_extra_info('peername')
    print(f"New connection from {address}")

    # Send messages
    try:
        while True:
            message=input('> ')
            if message.lower() == 'exit':
                    break
            try:
                out=encryptor(message,key,nonce,associated_data)
                print(out)
                writer.write(out)
                await writer.drain()
            except:
                continue
    except asyncio.CancelledError:
        print(f'''Connection closed from {address}''')
        pass

# Init program
async def main():
    server = await asyncio.start_server(handle_clients, 'localhost', 8888)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())
