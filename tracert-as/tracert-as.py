import argparse
import socket
import sys
import queue
import threading
import re

WHOIS_SERVER = re.compile(r'whois\.[\w]+\.net')
NETNAME = re.compile(r'netname:\s*(\S+)', re.IGNORECASE)
ORIGIN = re.compile(r'origina?s?:\s*(\S+)', re.IGNORECASE)
COUNTRY = re.compile(r'country:\s+(\S+)', re.IGNORECASE)


class ICMP:
    TEST_DATA = 'test data for icmp packet6'

    def __init__(self,
                 icmp_type=8,
                 code=0,
                 identifier=0,
                 seq_num=1,
                 data=TEST_DATA):
        self.type = icmp_type
        self.code = code
        self.identifier = identifier << 8
        self.seq_num = seq_num << 8
        self.data = data.encode('utf-8')

    def make_packet(self):
        packet = bytearray()
        packet.append(self.type)
        packet.append(self.code)
        packet.extend(self.calculate_checksum())
        packet.extend(self.identifier.to_bytes(2, 'big'))
        packet.extend(self.seq_num.to_bytes(2, 'big'))
        packet.extend(self.data)

        return packet

    def calculate_checksum(self):
        checksum = self.type << 8
        checksum += self.code
        checksum += self.identifier
        checksum += self.seq_num

        for i in range(0, len(self.data), 2):
            checksum += (self.data[i] << 8) + self.data[i + 1]

        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + (checksum >> 16)

        return (~checksum & 0xffff).to_bytes(2, 'big')

    @staticmethod
    def unpack(packet):
        icmp_info = packet[20:28]

        return ICMP(icmp_info[0],
                    icmp_info[1],
                    int.from_bytes(icmp_info[4:6], 'big'),
                    int.from_bytes(icmp_info[6:8], 'big'))


class WhoIs:
    def __init__(self, ip):
        self.ip = ip

    def get_whois_info(self):
        server = self.get_whois_server()

        if server == 'local':
            return 'local'

        return self.parse_data(self.get_data(server))

    def parse_data(self, data):
        fields = WhoIs.get_fields(data)

        if not fields:
            new_server = WHOIS_SERVER.search(data)

            if not new_server:
                return 'local'
            else:
                new_server = new_server.group(0)

            new_data = self.get_data(new_server)
            fields = WhoIs.get_fields(new_data)

            if not fields:
                return 'local'
        return fields

    @classmethod
    def get_fields(cls, data):
        netname_match = NETNAME.search(data)
        origin_match = ORIGIN.search(data)
        country_match = COUNTRY.search(data)

        if not netname_match or not origin_match or not country_match:
            return ''

        return ' '.join([netname_match.group(1),
                        origin_match.group(1),
                        country_match.group(1)])

    def get_data(self, host):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2.0)
            sock.connect((host, 43))
            sock.sendall(socket.gethostbyname(self.ip).encode() + b'\n')
            data = bytearray()
            while True:
                try:
                    raw_data = sock.recv(1024)
                    if not raw_data:
                        break
                    data.extend(raw_data)
                except socket.timeout:
                    return
            return data.decode(errors='replace')

    def get_whois_server(self):
        if self.is_local():
            return 'local'

        data = self.get_data('whois.iana.org')
        if not data:
            return 'local'

        match = WHOIS_SERVER.search(data)
        if match:
            return match.group(0)
        else:
            return 'local'

    @classmethod
    def get_info(cls, data):
        res = []
        netname_match = NETNAME.search(data)
        origin_match = ORIGIN.search(data)
        country_match = COUNTRY.search(data)

        if not netname_match or origin_match or country_match:
            return 'local'

        res.append(netname_match.group(1))
        res.append(origin_match.group(1))
        if country_match.group(1) != 'EU':
            res.append(country_match.group(1))
        return ' '.join(res)

    def is_local(self):
        octets = list(map(int, self.ip.split('.')))
        if (
                octets[0] == 10 or
                octets[0] == 172 and 16 <= octets[1] <= 31 or
                octets[0] == 192 and octets[1] == 168 or
                octets[0] == 100 and 64 <= octets[1] <= 127
        ):
            return True
        return False


class TracertAS:
    def __init__(self, destination, ttl=30):
        self.ttl = ttl
        try:
            self.destination = socket.gethostbyname(destination)
        except socket.error:
            print(f'Invalid value: {destination}', file=sys.stderr)
            exit(1)
        self.client = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.counter = 1
        self.path = queue.Queue()

        self.thread = threading.Thread(target=self.print_ip_info)
        self.thread.setDaemon(True)

    def get_traceroute_path(self):
        print(f'Tracerouting to {self.destination}. TTl = {self.ttl}.')
        self.thread.start()

        packet = ICMP().make_packet()
        self.client.settimeout(2.0)
        for i in range(1, self.ttl + 1):

            self.client.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, i)
            self.client.sendto(packet, (self.destination, 0))

            try:
                answer, addr = self.get_answer()
                self.path.put(addr[0])

                if answer.type == 0 and addr[0] == self.destination:
                    self.client.close()
                    break
            except socket.timeout:
                self.path.put('*')
        self.client.close()

        self.thread.join()

    def get_answer(self):
        message, addr = self.client.recvfrom(1024)
        packet = ICMP.unpack(message)
        return packet, addr

    def print_ip_info(self):
        while self.counter < self.ttl + 1:
            if not self.path.empty():
                ip = self.path.get()
                if ip == '*':
                    print(f'{self.counter}. *\n')
                    self.counter += 1
                else:
                    print(f'{self.counter}. {ip}.\n'
                          f'{WhoIs(ip).get_whois_info()}\n')
                    if ip == self.destination:
                        break
                    self.counter += 1


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('destination', help='DNS-name or IP address.')
    args = arg_parser.parse_args()

    try:
        TracertAS(args.destination, 50).get_traceroute_path()
    except Exception as e:
        print(str(e), file=sys.stderr)
        exit(2)


if __name__ == '__main__':
    main()
