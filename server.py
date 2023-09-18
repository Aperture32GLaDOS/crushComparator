import transport
import encryption
import socket
import json
import threading
from events import Event

private = encryption.readRSAKeyFromFile("private.key")
public = encryption.readRSAKeyFromFile("public.key")
clients = []
eventList = []
lock = threading.Lock()


def handleEvents():
    while True:
        if len(eventList) > 0:
            lock.acquire()
            event = eventList.pop(0)
            if event.name == "client-failure":
                index = clients.index(event.context["client"])
                try:
                    clients[index].sendUpdate({"clientBehind": clients[index - 1].sock.getpeername()[0]})
                    clients[index - 1].sendUpdate({"clientAhead": clients[index].sock.getpeername()[0]})
                except IndexError:
                    pass
                clients.remove(event.context["client"])
            lock.release()




class Client:
    def __init__(self, sock, AESKey):
        self.sock = sock
        self.AESKey = AESKey
        self.mainThread = threading.Thread(target=(self.listen), daemon=True)
        self.mainThread.start()

    def sendMessage(self, message):
        transport.sendDynamicData(message.encode("utf-8"), "text", "utf-8", self.sock, self.AESKey)

    def sendUpdate(self, update):
        transport.sendDynamicData(json.dumps(update).encode("utf-8"), "update", "utf-8", self.sock, self.AESKey)


    def listen(self):
        try:
            while True:
                transport.receiveDynamicData(self.sock, self.AESKey)
        except:
            lock.acquire()
            eventList.append(Event("client-failure", {"client": self}))
            lock.release()

HOST = "0.0.0.0"
PORT = 6969

eventsThread = threading.Thread(target=handleEvents, daemon=True)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen()
while True:
    clientsock = sock.accept()[0]
    AESKey = clientsock.recv(32)
    clients.append(Client(clientsock, AESKey))
    if len(clients) == 1:
        pass
    else:
        clients[-2].sendUpdate({"clientAhead": clients[-1].sock.getpeername()[0]})
        clients[-1].sendUpdate({"clientBehind": clients[-2].sock.getpeername()[0]})
