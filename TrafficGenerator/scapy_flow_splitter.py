from scapy.all import *
import os
import argparse

class scapy_flow_splitter():
    def __init__(self,
                 pcapfile = None,
                 ):

        self.pcapfile = None
        if pcapfile != None:
            self.get_pcap_file(pcapfile)

    def get_pcap_file(self,
                      pcapfile):
        assert pcapfile != None, 'must specify pcap file'

        assert os.path.exists(pcapfile), '%s does not exist' %pcapfile
        self.pcapfile= rdpcap(pcapfile)

    def seperate_flows_by_ip_tuple(self):

        flows = {}
        iptuples = []
        i = 0
        for packet in self.pcapfile:
            if packet.haslayer(IP) == 1:
                ip1 = packet[IP].src
                ip2 = packet[IP].dst
                iptuple = sorted([ip1,ip2])

                if flows.get(str(iptuple)) == None:
                    flows[str(iptuple)]= []

                flows[str(iptuple)].append(packet)
        return flows

    def splitpcap(self,
                  pcapfile = None,
                  savelocation = '.'):
        print 'reading' , pcapfile
        self.get_pcap_file(pcapfile)
        assert self.pcapfile != None, 'must specify pcap file'
        print 'seperating', pcapfile
        flows = self.seperate_flows_by_ip_tuple()
        print 'splitting', pcapfile
        for key,value in flows.iteritems():
            key = key.replace(']','').replace('[','').replace(',','_').replace('\'','').strip()
            wrpcap('%s/%s_%s.pcap' %(savelocation,os.path.basename(pcapfile),key), value)



def main():
    #SET ALL DEFAULT VALUES
    RLENGTH = 1500

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", help="set pcap file", required=True)
    parser.add_argument("-l", "--savedir", help="specify directory to savfe files", default='.')

    args = parser.parse_args()
    self = scapy_flow_splitter()
    self.splitpcap(pcapfile=args.pcap,
                   savelocation=args.savedir)


if __name__ == '__main__':
    main()
