import socket
import threading
import sys
import argparse
import queue
from time import time
from datetime import date

TIME_CONST = (date(1970, 1, 1) - date(1900, 1, 1)).days * 24 * 3600


class ParserSNTP:
    def __init__(self, data, offset):
        self.data = data
        self.offset = offset
        self.mode = 0
        self.version = 0
        self.result = bytearray()

        self.get_sntp_info()

    def get_sntp_info(self):
        if len(self.data) < 48:
            raise ValueError
        self.version = int((self.data[0] >> 3) & 7)
        self.mode = int(self.data[0] & 7)
        if self.mode != 3:
            raise ValueError

        self.result.append(
            self.version << 3 | 4  # LI=0, VN (copied from request), Mode=4
        )
        self.result.append(0)  # stratum
        self.result.append(self.data[2])  # poll (copied from request)
        self.result.append(0)  # precision
        self.result.extend((0).to_bytes(4, 'big'))  # delay
        self.result.extend((0).to_bytes(4, 'big'))  # dispersion
        self.result.extend((0).to_bytes(4, 'big'))  # identifier
        self.result.extend((0).to_bytes(8, 'big'))  # reference timestamp
        self.result.extend(
            self.data[40:48]
        )  # originate timestamp (copied from transmit timestamp)

    def make_packet(self):
        self.result.extend(((TIME_CONST + int(time()) + self.offset) << 32)
                           .to_bytes(8, 'big'))  # receive timestamp
        self.result.extend(((int(time()) + self.offset + TIME_CONST) << 32)
                           .to_bytes(8, 'big'))  # transmit timestamp
        return bytes(self.result)


class Server:
    def __init__(self, server_port=123, offset=0):
        self.server_port = server_port
        self.offset = offset
        self.handlers_count = 5
        self.requests = queue.Queue()
        self.answers = queue.Queue()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.handlers = []

    def start(self):
        try:
            self.server.bind(('0.0.0.0', self.server_port))
        except PermissionError:
            print('You do not have sufficient permissions to run the program.',
                  file=sys.stderr)
            exit(2)
        for _ in range(self.handlers_count):
            handler = threading.Thread(target=self.message_handler)
            self.handlers.append(handler)
            handler.setDaemon(True)
            handler.start()
        print(f'Server has started on port {self.server_port}.\n'
              f'Offset in seconds: {self.offset}.\n')
        while True:
            try:
                data, address = self.server.recvfrom(1024)
                self.requests.put((data, address))
            except socket.error:
                pass

    def message_handler(self):
        while True:
            try:
                if not self.requests.empty():
                    data, address = self.requests.get(block=False)
                    print(f'Connected: {address[0]}.')
                    try:
                        answer = ParserSNTP(data, self.offset)
                    except ValueError:
                        self.server.sendto(
                            bytes('Something bad happened.\n'
                                  'Please try again.', 'utf-8'),
                            address
                        )
                        continue
                else:
                    continue
            except queue.Empty:
                pass
            else:
                self.server.sendto(answer.make_packet(), address)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', type=int, default=0)
    parser.add_argument('-p', '--port', type=int, default=123)
    args = parser.parse_args()

    if args.port < 1 or args.port > 65535:
        print('Enter correct port.', file=sys.stderr)
        exit(1)

    server = Server(args.port, args.time)
    try:
        server.start()
    except KeyboardInterrupt:
        server.server.close()
        print('Server has stopped.')


if __name__ == "__main__":
    main()
