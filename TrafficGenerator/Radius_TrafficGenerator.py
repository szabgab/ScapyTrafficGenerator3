import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from support.Scapy_Control import *
import sys, getopt

if __name__== "__main__":
    dmac = GenerateRandomMac()
    smac = GenerateRandomMac()
    SIP = GenerateRandomIp()
    DIP = GenerateRandomIp()
    dport = 1812
    sport = 16450
    id = 1
    Request = Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP) / UDP(dport=dport, sport=sport) / Radius(code=1, id=id)
    Challenge = Ether(dst=smac, src=dmac, type=0x0800) / IP(src=DIP, dst=SIP) / UDP(dport=sport, sport=dport) / Radius(code=11, id=id, authenticator='0123456789abcdef')
    id += 1
    Request2 = Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP) / UDP(dport=dport, sport=sport) / Radius(code=1, id=id, authenticator='fedcba9876543210')
    Accept = Ether(dst=smac, src=dmac, type=0x0800) / IP(src=DIP, dst=SIP) / UDP(dport=sport, sport=dport) / Radius(code=2, id=id)

    p = [Request, Challenge, Request2, Accept]

    wrpcap('/home/nathan/radius.pcap', p)
