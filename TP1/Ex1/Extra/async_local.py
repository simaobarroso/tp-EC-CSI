import ascon
import random
import asyncio
import hashlib
import nest_asyncio

nest_asyncio.apply()

hashlength=16
sent_nounces=[]

def calculate_sha256(message):
    if isinstance(message, str):
        message = message.encode()

    sha256_hash = hashlib.sha256(message).hexdigest()
    return sha256_hash

def cipher_message(in_message,key):
    associated_data=calculate_sha256(in_message).encode()
    # Message is repeated
    if in_message=="repeat_test":
        nounce=sent_nounces[-1]
    else:
        nounce_seed=str(random.getrandbits(128))
        nounce=ascon.hash(nounce_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)

    try:
        out_message=ascon.encrypt(key, nounce, associated_data, in_message.encode(), variant="Ascon-128")
        print(f"Sending: {in_message}")

        # Message data is altered
        if in_message=="altered_test":
            print(f"Original >>> ({out_message},{nounce},{associated_data})")
            out_message=out_message[:2]+(f'{out_message[2]+1}'.encode())+out_message[3:]

        print(f"Outgoing >>> ({out_message},{nounce},{associated_data})")
        sent_nounces.append(nounce)
    except Exception as e:
        print(e)
    
    return (out_message,nounce,associated_data)

def read_message(text,key,nounce,associated_data):
    print(f"Incoming <<< ({text},{nounce},{associated_data})")
    try:
        out_message=ascon.decrypt(key, nounce, associated_data, text, variant="Ascon-128")
    except Exception as e:
        return "[ERROR] Message could not be decrypted"
    if out_message==None and calculate_sha256(out_message.decode())!=associated_data.decode():
        return "[ERROR] Message has been tampered"
    return out_message.decode()

async def emitter(queue,key):
    loop = asyncio.get_event_loop()
    while True:
        message=await loop.run_in_executor(None, input, "Message to send > ")
        out=cipher_message(message,key)
        await queue.put(out)
        if message=="exit":
            break

async def receiver(queue,key):
    known_nounces=[]
    while True:
        message,nounce,associated_data=await queue.get()
        if nounce in known_nounces:
            print("Repeated nounce, ignoring message")
        else:
            known_nounces.append(nounce)
            text=read_message(message,key,nounce,associated_data)
            print(f"Received: {text}")
        if text=="exit":
            break

async def main():
    queue = asyncio.Queue()
    key_seed=input("Seed for key > ")
    key=ascon.hash(key_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)
    print(f"Session Key: {key}")
    # Create separate tasks for emitter and receiver
    emitter_task = asyncio.create_task(emitter(queue, key))
    receiver_task = asyncio.create_task(receiver(queue, key))
    # Wait for both tasks to complete
    await asyncio.gather(emitter_task, receiver_task)
    print("All tasks completed")


asyncio.run(main())    
    