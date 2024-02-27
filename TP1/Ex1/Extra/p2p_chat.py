import ascon
import random
import hashlib
import threading
import socket

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

    return out_message+nounce+associated_data

def read_message(text,key,nounce,associated_data):
    print(f"Incoming <<< ({text},{nounce},{associated_data})")
    try:
        out_message=ascon.decrypt(key, nounce, associated_data, text, variant="Ascon-128")
    except Exception as e:
        return "[ERROR] Message could not be decrypted"
    if out_message==None and calculate_sha256(out_message.decode())!=associated_data.decode():
        return "[ERROR] Message has been tampered"
    return out_message.decode()

def emitt(key):
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = input("Input server address: ")
        port = int(input("Input server port: "))
        try:
            client.connect((address, port))
            conected=True
        except:
            print("Could not connect to server")
            conected=False
        while conected:
            message=input("Message to send > ")
            out=cipher_message(message,key)
            client.sendall(out)
            if message=="exit":
                conected=False


def listen(server, key):
    known_nounces=[]
    while True:
        server.listen()
        conn, addr = server.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message=data[:-80]
                nounce=data[-80:-64]
                associated_data=data[-64:]
                if nounce in known_nounces:
                    print("Repeated nounce, ignoring message")
                else:
                    known_nounces.append(nounce)
                    text=read_message(message,key,nounce,associated_data)
                    print(f"Received: {text}")
                if text=="exit":
                    break


def main(port):
    #Create asyncio socket to communicate
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', port))
    #input key
    key_seed=input("Seed for key > ")
    key=ascon.hash(key_seed.encode(),variant="Ascon-Xof", hashlength=hashlength)
    print(f"Session Key: {key}")
    #Listen thread
    listen_thread = threading.Thread(target=listen, args=(server, key)).start()
    #Sender thread
    sender_thread = threading.Thread(target=emitt, args=(key,)).start()

if __name__ == "__main__":
    port = int(input("Input server port: "))
    main(port)

