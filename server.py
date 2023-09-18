import transport
import encryption
import socket

private = encryption.readRSAKeyFromFile("private.key")
public = encryption.readRSAKeyFromFile("public.key")

HOST = "0.0.0.0"
PORT = 6969

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen()
client = sock.accept()[0]
client.send("idk".encode())
