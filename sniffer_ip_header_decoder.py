import ipaddress
import os
import socket
import struct
import sys

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        # Move 8 bits from byte 4 to right and get left half-byte
        self.ver = header[0] >> 4
        # multiply 8 bits header[0] times 00001111 and get right half-byte
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # IP address readable for human
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


def sniff(host):
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

    sniffer.bind((host, 0))

    # we want the IP headers included in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if we're using Windows, we need to send an IOCTL
    # to set up promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # read in a single packet
            raw_buffer = sniffer.recvfrom(65565)[0]

            # create an IP header from the first 20 bytes of the buffer
            ip_header = IP(raw_buffer[0:20])

            # print out the protocol that was detected and the hosts
            print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                                ip_header.src_address,
                                                ip_header.dst_address))

    # handle CTRL-C
    except KeyboardInterrupt:
        # if we're using Windows, turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '10.0.2.15'
    sniff(host)
