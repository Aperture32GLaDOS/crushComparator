import threading
import transport
import encryption
import socket
import json
import time
import os
from events import Event
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import gnupg

gpg = gnupg.GPG(gnupghome="/home/eric/.gnupg")

lock = threading.Lock()

public = encryption.readRSAKeyFromFile("public.key")

HOST = "127.0.0.1"
PORT = 6969

eventList = []

def handleEvents():
    while True:
        if len(eventList) > 0:
            lock.acquire()
            eventList.pop(0)
            lock.release()


class Client:
    def __init__(self, sock, secret=None, do_handshake=False):
        self.sock = sock
        self.secret = secret
        self.listenThread = threading.Thread(target=self.listen, daemon=True)
        self.doHandshake = do_handshake

    def listen(self):
        if self.doHandshake:
            getSharedSecret(self)
        while True:
            received = self.sock.recv(1)
            if received == b"\x01":
                private_key = ec.generate_private_key(
                ec.SECP384R1()
                )
                
                public_key_and_signature = self.sock.recv(927).decode("utf-8")
                if not gpg.verify(public_key_and_signature, extra_args=["-o", "./data"]):
                    status = gpg.verify(public_key_and_signature, extra_args=["-o", "./data"])
                    print(status)
                    print("UNTRUSTED SIGNATURE!")
                    exit()
                with open("data", "rb") as file:
                    public_key_data = file.read()
                os.remove("data")

                self.sock.send(gpg.sign(private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )).data)

                public_key = serialization.load_pem_public_key(public_key_data)
                shared_key = private_key.exchange(ec.ECDH(), public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'handshake data',
                ).derive(shared_key)
                self.secret = derived_key
                # If the client is at the end of the queue
                if client_behind is not None and client_behind.secret is not None:
                    if client_ahead is None:
                        # Back-transmit the new shared secret
                        hashedCrushName = encryption.hashStringWithSHA((crush + name), self.secret)
                        hashedNameCrush = encryption.hashStringWithSHA((name + crush), self.secret)
                        transport.sendDynamicData(hashedCrushName.encode("utf-8"), "newCrushName", "utf-8", sock, AESKey)
                        transport.sendDynamicData(hashedNameCrush.encode("utf-8"), "newNameCrush", "utf-8", sock, AESKey)
                        print("Sent crush info to server")
                        client_behind.sock.send(b"\x02")
                        transport.sendEncryptedData(self.secret, client_behind.sock, client_behind.secret)
                        client_behind.secret = self.secret
                # If there is no client behind, then all clients are up-to-date
                else:
                    hashedCrushName = encryption.hashStringWithSHA((crush + name), self.secret)
                    hashedNameCrush = encryption.hashStringWithSHA((name + crush), self.secret)
                    transport.sendDynamicData(hashedCrushName.encode("utf-8"), "newCrushName", "utf-8", sock, AESKey)
                    transport.sendDynamicData(hashedNameCrush.encode("utf-8"), "newNameCrush", "utf-8", sock, AESKey)
                    print("Sent crush info to server")
                    transport.sendDynamicData("clients-updated".encode("utf-8"), "info", "utf-8", sock, AESKey)
            if received == b"\x02":
                self.secret = transport.receiveEncryptedData(32, self.sock, self.secret)
                if client_behind is not None and client_behind.secret is not None:
                    if self.secret is None:
                        self.secret = client_ahead.secret
                    hashedCrushName = encryption.hashStringWithSHA((crush + name), self.secret)
                    hashedNameCrush = encryption.hashStringWithSHA((name + crush), self.secret)
                    transport.sendDynamicData(hashedCrushName.encode("utf-8"), "newCrushName", "utf-8", sock, AESKey)
                    transport.sendDynamicData(hashedNameCrush.encode("utf-8"), "newNameCrush", "utf-8", sock, AESKey)
                    print("Sent crush info to server")
                    client_behind.sock.send(b"\x02")
                    transport.sendEncryptedData(self.secret, client_behind.sock, client_behind.secret)
                    client_behind.secret = self.secret

                # If there is no client behind, then all clients are up-to-date
                else:
                    hashedCrushName = encryption.hashStringWithSHA((crush + name), self.secret)
                    hashedNameCrush = encryption.hashStringWithSHA((name + crush), self.secret)
                    transport.sendDynamicData(hashedCrushName.encode("utf-8"), "newCrushName", "utf-8", sock, AESKey)
                    transport.sendDynamicData(hashedNameCrush.encode("utf-8"), "newNameCrush", "utf-8", sock, AESKey)
                    print("Sent crush info to server")
                    transport.sendDynamicData("clients-updated".encode("utf-8"), "info", "utf-8", sock, AESKey)




def getSharedSecret(client):
    client.sock.send(b"\x01")
    private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    client.sock.send(gpg.sign(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )).data)

    public_key_and_signature = client.sock.recv(927).decode("utf-8")
    if not gpg.verify(public_key_and_signature, extra_args=["-o", "./data"]):
        status = gpg.verify(public_key_and_signature, extra_args=["-o", "./data"]).status
        print("UNTRUSTED SIGNATURE!")
        exit()
    with open("data", "rb") as file:
        public_key_data = file.read()
    os.remove("data")
    public_key = serialization.load_pem_public_key(public_key_data)
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    client.secret = derived_key
    print("Shared secret obtained!")


client_ahead = None
client_behind = None
name = input("What is your name: ")
crush = input("Who is your crush: ")

AESKey = encryption.generateKey()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send(AESKey)
while True:
    received = transport.receiveDynamicData(sock, AESKey)
    if received[0] == "update":
        data = json.loads(received[-1].decode(received[1]))
        changed = False
        try:
            data["clientAhead"]
            client_ahead = Client(socket.socket(socket.AF_INET, socket.SOCK_STREAM), None, True)
            client_ahead.sock.bind((data["clientAhead"], data["port"]))
            print("Server port running on " + str(data["port"]))
            client_ahead.sock.listen()
            client_ahead.sock = client_ahead.sock.accept()[0]
            client_ahead.listenThread.start()
            changed = True
        except KeyError:
            pass
        try:
            data["clientBehind"]
            client_behind = Client(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            print("Connecting to port " + str(data["port"]))
            time.sleep(1)
            client_behind.sock.connect((data["clientBehind"], data["port"]))
            client_behind.listenThread.start()
            changed = True
        except KeyError:
            pass
    else:
        print(received[-1].decode(received[1]))
