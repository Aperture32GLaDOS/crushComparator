import transport
import encryption
import socket

private = encryption.readRSAKeyFromFile("private.key")
public = encryption.readRSAKeyFromFile("public.key")
clients = []

class Client:
    def __init__(self, sock, AESKey):
        self.sock = sock
        self.AESKey = AESKey

    def sendMessage(self, message):
        transport.sendDynamicData(message.encode("utf-8"), "text", "utf-8", self.sock, self.AESKey)

HOST = "0.0.0.0"
PORT = 6969

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen()
while True:
    clientsock = sock.accept()[0]
    AESKey = clientsock.recv(32)
    clients.append(Client(clientsock, AESKey))
