import socket
import getopt
import sys

# ADDRESS & PORT are only modified in process_args()
ADDRESS = "127.0.0.1"
PORT = 8080

def usage():
    txt = """\nWelcome! Usage instructions can be seen below."""
    print(txt)
    print("-------------------------------------------")
    print("usage: python covert.py [options]")
    print("\t-h  --help   show usage")


def process_args(argv):
    SERVER_MODE = False
    try:
        opts, args = getopt.getopt(argv, "h", ["help", "server", "client"])
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
        else:
            assert False, "Unhandled option"
    return SERVER_MODE


if __name__ == "__main__":
    mode = process_args(sys.argv[1:])
    print(mode)
