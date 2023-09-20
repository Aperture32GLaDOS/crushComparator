import transport
import encryption
import socket
import json
import threading
import time
import random
from events import Event

private = encryption.readRSAKeyFromFile("private.key")
public = encryption.readRSAKeyFromFile("public.key")
clients = []
eventList = []
# A dictionary which stores crush+name values and links them to the clients who sent them
crushNames = {}
# A dictionary which stores name+crush values and links them to the clients who sent them
nameCrushes = {}
lock = threading.Lock()


def handleEvents():
    while True:
        time.sleep(0.5)
        if len(eventList) > 0:
            lock.acquire()
            event = eventList.pop(0)
            # If a client has disconnected or otherwise shutdown
            if event.name == "client-failure":
                index = clients.index(event.context["client"])
                # Re-connect the p2p linked list
                try:
                    clients[index].sendUpdate({"clientBehind": clients[index - 1].sock.getpeername()[0]})
                    clients[index - 1].sendUpdate({"clientAhead": clients[index].sock.getpeername()[0]})
                except IndexError:
                    pass
                except BrokenPipeError:
                    pass
                # And remove any mention of the client
                clients.remove(event.context["client"])
                crushNames.clear()
                nameCrushes.clear()
            # If the p2p linked list has updated its shared secret,
            if event.name == "client-update":
                # Check for successful pairs
                for crushName in crushNames.keys():
                    try:
                        client1 = nameCrushes[crushName]
                        client2 = crushNames[crushName]
                        transport.sendDynamicData("success".encode("utf-8"), "pair", "utf-8", client1.sock, client1.AESKey)
                        transport.sendDynamicData("success".encode("utf-8"), "pair", "utf-8", client2.sock, client2.AESKey)
                    except KeyError:
                        continue
                crushNames.clear()
                nameCrushes.clear()
            lock.release()




class Client:
    def __init__(self, sock, AESKey):
        self.sock = sock
        self.AESKey = AESKey
        self.port = random.randint(2000, 60000)
        self.mainThread = threading.Thread(target=(self.listen), daemon=True)
        self.mainThread.start()

    def sendMessage(self, message):
        transport.sendDynamicData(message.encode("utf-8"), "text", "utf-8", self.sock, self.AESKey)

    def sendUpdate(self, update):
        transport.sendDynamicData(json.dumps(update).encode("utf-8"), "update", "utf-8", self.sock, self.AESKey)


    def listen(self):
        try:
            while True:
                dataType, encoding, data = transport.receiveDynamicData(self.sock, self.AESKey)
                if dataType == "info":
                    if data.decode(encoding) == "clients-updated":
                        lock.acquire()
                        eventList.append(Event("client-update", {}))
                        lock.release()
                        print("P2P linked list shared secret updated")
                        
                elif dataType == "newCrushName":
                    print("New info from client")
                    crushNames[data.decode(encoding)] = self
                elif dataType == "newNameCrush":
                    nameCrushes[data.decode(encoding)] = self
        except:
            lock.acquire()
            print("Client disconnected")
            eventList.append(Event("client-failure", {"client": self}))
            lock.release()

HOST = "0.0.0.0"
PORT = 6969

eventsThread = threading.Thread(target=handleEvents, daemon=True)
eventsThread.start()

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
        clients[-2].sendUpdate({"clientAhead": clients[-1].sock.getpeername()[0], "port": clients[-1].port})
        clients[-1].sendUpdate({"clientBehind": clients[-2].sock.getpeername()[0], "port": clients[-1].port})
        crushNames.clear()
        nameCrushes.clear()
