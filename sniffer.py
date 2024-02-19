import os
import socket

# Host for listening
HOST = '10.0.2.15'

def main():
    # Create raw socket and connect it with public interface
    if os.name == 'nt': # for Windows
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    # Steal the IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if Windows -> send IOCTL call to network card to turn ON limitless mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Load single packet and print it - without decoding
    print(sniffer.recvfrom(65565))

    # If use Windows system, turn OFF limitless mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == '__main__':
    main()