import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


class VlanTag():
    def __init__(self,
                 packets,
                 vlanTag=1,
                 vlanTagType=2048):
        self.packets=packets
        self.attach_VLAN(vlanTag=vlanTag,
                         vlanTagType=vlanTagType)
    def attach_VLAN(self,
                   vlanTag=1,
                    vlanTagType=2048):
        # loop throught all packets and attach a gre layer to it
        inserted_packets = []
        for PACKET in self.packets:
            # lets get ether payloac
            etherpayload = PACKET.payload

            #let remove the payload, insert layers, add payload
            PACKET.remove_payload()
            PACKET.add_payload(Dot1Q(vlan= vlanTag,type=vlanTagType)/ etherpayload)

            #PACKET[etherlayer_location - 1].remove_payload()
            #PACKET[etherlayer_location - 1].add_payload(insert_layers)
            #inserted_packets.append(packet)


        #self.packets = inserted_packets
        return self.packets