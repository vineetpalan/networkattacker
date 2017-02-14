from scapy.all import *
from netfilterqueue import NetfilterQueue

def modify(packet):
    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string

    #modify the packet all you want here

    packet.set_payload(str(pkt)) 

    packet.accept() 



nfqueue = NetfilterQueue()

nfqueue.bind(0, modify) 
try:
    print "[*] waiting for data"
    nfqueue.run()
except KeyboardInterrupt:
    pass