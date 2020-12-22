import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Scapy_Control import *

class Gre_Encapsulate():
    def __init__(self,
                 packets,
                 chksum_present=1,
                 proto=0x0800):
        self.packets = packets
        self.attach_gre()

    def attach_gre(self,
                   chksum_present=1,
                   proto=0x0800):
        # loop throught all packets and attach a gre layer to it
        GREEND = GenerateRandomIp()
        GREEND2 = GenerateRandomIp()
        inserted_packets = []
        for PACKET in self.packets:
            # get packet layer count
            layer_count = len(PACKET[0].summary().split('/'))
            # find first ip layer
            iplayer = PACKET[IP]
            iplayer_location = None
            assert int(iplayer.proto) != 47, 'gre tunneling is already encapsulated, dont encapsulate again'
            for i in range(layer_count):
                if iplayer == PACKET[i:]:
                    iplayer_location=i
                    break

            # now lets attach a ip/Gre layer to packet
            insert_layers = IP(src=GREEND,
                               dst=GREEND2,
                               proto="gre")/\
                            GRE(chksum_present=chksum_present,
                                proto=proto)
            insert_layers.add_payload(iplayer)
            PACKET[iplayer_location - 1].remove_payload()
            PACKET[iplayer_location - 1].add_payload(insert_layers)
            inserted_packets.append(PACKET)
        self.packets = inserted_packets
        return self.packets

if __name__ == "__main__":
    packets = rdpcap('../Pcaps/imap.pcap')
    self = Gre_Encapsulate()
    self.load_packets(packets)
    self.attach_gre()
    wrpcap('/home/nathan/Downloads/test.pcap', self.packets)








        #get packet ip src and dest