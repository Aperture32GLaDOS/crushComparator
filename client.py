import transport
import encryption
import socket

public = encryption.readRSAKeyFromFile("public.key")

HOST = "127.0.0.1"
PORT = 6969

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print(sock.recv(3))
