import transport
import encryption
import socket
import json

public = encryption.readRSAKeyFromFile("public.key")

HOST = "127.0.0.1"
PORT = 6969

client_ahead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_behind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

AESKey = encryption.generateKey()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send(AESKey)
while True:
    received = transport.receiveDynamicData(sock, AESKey)
    if received[0] == "update":
        data = json.loads(received[-1].decode(received[1]))
        if client_ahead is not None:
            try:
                client_ahead.bind((data["clientAhead"], 0))
            except IndexError:
                pass
        if client_behind is not None:
            try:
                client_behind.bind((data["clientBehind"], 0))
            except IndexError:
                pass
    else:
        print(received[-1].decode(received[1]))
