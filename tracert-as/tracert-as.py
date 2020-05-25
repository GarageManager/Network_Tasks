import argparse
import socket


class Traceroute:
    TTL = 30

    def __init__(self, destination):
        self.destination = destination
        self.get_traceroute_path()

    def get_traceroute_path(self):
        print(socket.gethostbyaddr(self.destination))
        # client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # client.connect()


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('destination',
                            help='Source DNS-name or IP address.')
    args = arg_parser.parse_args()
    Traceroute(args.destination)


if __name__ == '__main__':
    main()
