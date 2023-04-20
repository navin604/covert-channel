import socket
import getopt
import sys
from scapy.layers.inet import UDP

# ADDRESS & PORT are only modified in process_args()
ADDRESS = "127.0.0.1"
PORT = 8080


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

def server():
    pass


def client():
    pass


def usage():
    txt = """\nWelcome! Usage instructions can be seen below."""
    print(txt)
    print("-------------------------------------------")
    print("usage: python covert.py [options]")
    print("\t-h  --help   show usage")


def process_args(argv):
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
            PORT = a
        elif o == "--file":
            file = a
        else:
            assert False, "Unhandled option"
    return SERVER_MODE, file


if __name__ == "__main__":
    mode, file = process_args(sys.argv[1:])
    main(mode, file)
