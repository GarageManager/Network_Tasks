import argparse
import socket


class Traceroute:
    TTL = 30

    def __init__(self, destination):
        self.destination = destination
        self.get_traceroute_path()

    def get_traceroute_path(self):
        client = socket.socket()
        client.sendto(b'', self.destination)
        while True:
            data = client.recvfrom(1024)
            print(data)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('destination',
                            help='Source DNS-name or IP address.')
    args = arg_parser.parse_args()
    Traceroute(args.destination)


if __name__ == '__main__':
    main()
