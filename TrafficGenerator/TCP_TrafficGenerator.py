import logging

import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ScapyPacketGenerator import *

MTU = 1500


def main(argv):
    #initiate class
    self = ScapyPacketGenerator()
    #declare default values

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="set replay interface", required=False,default='eth2' )
    parser.add_argument("-r", "--syncattack", help="specify sync attack attempt", required=False, default=False)
    parser.add_argument("-s", "--src", help="specify src ip", required=False, default=GenerateRandomIp())
    parser.add_argument("-d", "--dst", help="specify dst ip", required=False, default=GenerateRandomIp() )
    parser.add_argument("-S", "--sport", help="specify src port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-D", "--dport", help="specify dst port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-m", "--srcmac", help="specify src mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-M", "--dstmac", help="specify dst mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-p", "--packetdata",  help='packet data', required=False, default="HELLOSERVER:HELLOCLIENT")
    parser.add_argument("-B", "--dstipv6", help="dst ipv6", required=False, default = None)
    parser.add_argument("-b", "--srcipv6", help="src ipv6", required=False, default = None)
    parser.add_argument("-A", "--setipv6", help="specify ipv6 transfer", required=False, default=False, action="store_true")

    args, unknown = parser.parse_known_args()
    #args = parser.parse_args()

    self.INTF = args.interface
    # list IPS
    # list IPS
    SIPS = []
    DIPS = []
    # Set ipv6 vals
    if args.srcipv6 != None or args.dstipv6 != None or args.setipv6:
        if args.srcipv6 != None:
            SIPS.append(args.srcipv6)
        else:
            SIPS.append(GenerateRandomIpv6())
        if args.dstipv6 != None:
            DIPS.append(args.dstipv6)
        else:
            DIPS.append(GenerateRandomIpv6())


        IPV6TEST = True
    # Set ipv4 vals
    else:
        # list SIPS
        if '/' in str(args.src):
            SIP, Netmask = args.src.split('/')
            SIPS = GetIpsInNetwork(ip = SIP,
                                   netmask = Netmask)
        else:
            SIPS.append(str(args.src))

        IPV6TEST = False


        # list DIPS
        DIPS = []
        if '/' in str(args.dst):
            DIP, Netmask = args.dst.split('/')
            DIPS = GetIpsInNetwork(ip = DIP,
                                   netmask = Netmask)
            print DIPS
        else:
            DIPS.append(str(args.dst))
    SendData=[]
    if ':' in args.packetdata:
        SendData.append(args.packetdata.split(':'))
    else:
        SendData.append([args.packetdata,None])

    print 'sips', SIPS
    print 'dips', DIPS
    for SIP in SIPS:
        for DIP in DIPS:
            self.TCP.SetVariables(dmac = args.dstmac,
                                   smac = args.srcmac,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = args.sport,
                                   dport = args.dport,
                                   SendData = SendData,
                                   )
            self.Packets = self.TCP.Test()
            print 'playing on interface', self.INTF
            self.SendPackets()


if __name__ == '__main__':
    main(sys.argv[1:])