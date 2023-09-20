### The Crush Comparator
This program is designed to be used in semi-large groups of people (or at least, more than just two) to find mutual crushes
It is designed in such a way that a crush will only be revealed to anyone if it is mutual

## The Methodology
The program works by using a hybrid of client-server and P2P architectures. In both the client-server and P2P architecture, there is a shared secret. This means that the main server cannot find anything about any crushes due to the P2P shared secret, and the peers can't find anything due to the client-server shared secrets.
It finds mutual crushes by comparing salted hashes (the salt is the shared secret from the P2P architecture)
You can imagine how it works with an example; imagine that Alice likes Bob and Bob likes Alice back. From Alice's perspective, her name + her crushes name is AliceBob. From Bob's perspective, his crushes name + his name is AliceBob. They are identical, so their hash will also be identical.

## How to Use
Ideally, it will be done on the same LAN due to port-forwarding reasons. If not, then a part of the code must be rewritten, as currently the server designates a random port for the clients in the P2P architecture.
Run the server code as-is, but make sure to change the client.py code so that the line HOST = "127.0.0.1" is changed to HOST = "*ENTER SERVER IP*"
When running the client code, if there is a pair you will receive a message which simply says "success"
