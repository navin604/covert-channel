# Covert channel

## What is it

This application is a basic covert channel which is used to send encrypted data hidden in the source port field of UDP packets.
It offers both client and server mode. Client mode is used to send data from a file to the server which receives this data and stores it to a file. 
Each line is encrypted and then converted to a hex string. Each character within this string is then converted into its respective
ASCII value and then embedded in a packet using Scapy.

## Prerequisites

You must have the following installed:

- [Scapy](https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x)


## Usage

Client mode:
    
    python covert.py --file <file> --ip <target ip> --port <target port>

Server mode:
  
    python covert.py --server --file <file> --port <port to listen on>
    
