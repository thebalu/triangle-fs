# In-network data store

## Motivation

The goal of our project is to create a proof of concept in-network data store, that circulates data in packets between switches organized in loops on the network. It can be thought of as a key-value store, where there are a finite number of unique keys, representing some information stored in a packet. In our model, we can add a packet to the network, then query or remove it by its key.

## Dependencies and prerequisites
- P4
- Python

 To read more about how to obtain the required software please visit https://github.com/p4lang/tutorials#obtaining-required-software
 
 ## Getting started
 
 In order to try out our application, simply build the code with a `make` command and then type `xtrem h1 h4`.
 Start listening on host h4 by typing `python receive.py`
 You can send packets on host h1 and whenever you want to query a packet, it will appear on host h4.
 ### Sending a packet:
 You can:
 - send in a new packet: `python send.py --packet_id <packet_id> <message>`
 - query an existing packet: `python send.py --packet_id <packet_id> --query <message>`
 - delete an existing packet: `python send.py --packet_id <packet_id> --delete <message>`
 
