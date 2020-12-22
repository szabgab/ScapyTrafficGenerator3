import logging

import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ScapyPacketGenerator import *

MTU = 1500




def main():
    #SET ALL DEFAULT VALUES
    RLENGTH = 1500

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="set replay interface", required=False,default='eth2' )
    parser.add_argument("-s", "--src", help="specify src ip", required=False, default=GenerateRandomIp())
    parser.add_argument("-d", "--dst", help="specify dst ip", required=False, default=GenerateRandomIp() )
    parser.add_argument("-S", "--sport", help="specify src port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-D", "--dport", help="specify dst port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-m", "--srcmac", help="specify src mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-M", "--dstmac", help="specify dst mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-X", "--method", help="specify method", required=False, default=1)
    parser.add_argument("-F", "--file", help="specify file to transfer", required=False, action='append', default = ['/opt/TrafficGen/TestFiles/Malicious_DOC.doc'])
    parser.add_argument("-t", "--type", help="specify type", required=False, default='IPv4')
    parser.add_argument("-q", "--clientseq", help="specify starting client SEQ", required=False, default = 1)
    parser.add_argument("-Q", "--serverseq", help="specify starting server SEQ", required=False, default = 1)
    parser.add_argument("-B", "--dstipv6", help="dst ipv6", required=False, default = None)
    parser.add_argument("-b", "--srcipv6", help="src ipv6", required=False, default = None)
    parser.add_argument("-A", "--setipv6", help="specify ipv6 transfer", required=False, default=False, action="store_true")
    parser.add_argument("-o", "--scapyoutput", help="specify output file", required=False, default=True, action="store_false")
    parser.add_argument("-x", "--pps", help="specify speed of replay in packets per second", required=False, default=None)
    parser.add_argument("-v","--vlanTag", help="specify vlan tag id", required=False, default=None)
    parser.add_argument("-N","--cn", help="commone name", required=False, default = "nathan_is_awesome")
    parser.add_argument("-I", "--issuer", help="issuer", required=False, default = 'nathan_is_the_best.com')
    parser.add_argument("-V", "--version", help="ssl version", required=False, default = 'TLS_1_0')

    args = parser.parse_args()

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

    INTF = str(args.interface)

    FILE = []
    for f in args.file:
        F = f.split(':')
        if len(F)==1:
            FILE.append(F[0].strip('\n'))
            if str(F[0]).lower() != 'none':
                assert os.path.exists(F[0]), '%s does not exist' %F[0]
        elif len(F)==2:
            if str(F[0]).lower() == 'random':
                DATAONLY = int(F[1])
                FILE.append('random')
            else:
                if str(F[0]).lower() != 'none':
                    if str(F[0]).lower() != '/opt/TrafficGen/TestFiles/Malicious_DOC.doc':
                        assert os.path.exists(F[0]), '%s does not exist' %F[0]
                randomized = int(F[1].strip('\n'))
                FILE.append(F[0].strip('\n'))

    #lets strip the default if needed
    if len(FILE) > 1:
        FILE.remove('/opt/TrafficGen/TestFiles/Malicious_DOC.doc')




    if int(args.method) == 1:
        METHOD = 'GET'
    elif int(args.method) == 2:
        METHOD = 'PUT'
    elif int(args.method) == 3:
        METHOD = 'POST'
    else:
        raise Exception('this module only supports https')


    if args.vlanTag != None:
        vlanTag= int(args.vlanTag)

        print 'attempting to set http traffic vlan to %s' %str(vlanTag)
    else:
        vlanTag = None

    if IPV6TEST == True:
        self = ''
        self = ScapyPacketGenerator()
        self.HTTPS.SetVariables(METHOD = METHOD,
                               dmac = args.dstmac,
                               smac = args.srcmac,
                               TYPE= args.type,
                               src = None,
                               dst = None,
                               srcv6 = SIPS[0],
                               dstv6 = DIPS[0],
                               sport = int(args.sport),
                               dport = 443,
                               INTF = args.interface,
                               FILES = FILE,
                               InitClientSeq=args.clientseq,
                               InitServerSeq=args.serverseq,
                               rlength = RLENGTH,
                               Verbose = args.pps,
                               vlanTag=vlanTag,
                               subject=args.cn,
                               issuer=args.issuer,
                               version=args.version,
        )

        self.SetupInterface(INTF = args.interface)
        self.Packets = self.HTTPS.HTTPS_TEST()



        if args.scapyoutput == True:

            if args.pps != None:
                self.SendPackets(pps=args.pps)
            else:
                self.SendPackets()
        else:
            if args.pps != None:
                self.SendPackets(pps=args.pps,Verbose = 0)
            else:
                self.SendPackets(Verbose = 0)

    else:
        print 'SIPS', SIPS
        print 'DIPS', DIPS
        for SIP in SIPS:
            for DIP in DIPS:
                self = ''
                self = ScapyPacketGenerator()
                self.HTTPS.SetVariables(METHOD = METHOD,
                                       dmac = args.dstmac,
                                       smac = args.srcmac,
                                       TYPE= args.type,
                                       src = SIP,
                                       dst = DIP,
                                       srcv6 = None,
                                       dstv6 = None,
                                       sport = args.sport,
                                       dport = 443,
                                       INTF = args.interface,
                                       FILES = FILE,
                                       InitClientSeq=args.clientseq,
                                       InitServerSeq=args.serverseq,
                                       rlength = RLENGTH,
                                       Verbose = args.pps,
                                       vlanTag=vlanTag,
                                       subject=args.cn,
                                       issuer=args.issuer,
                                       version=args.version,
                                       )
                self.SetupInterface(INTF = INTF)
                self.Packets  = self.HTTPS.HTTPS_TEST()



                if args.scapyoutput == True:

                    if args.pps != None:
                        self.SendPackets(pps=args.pps)
                    else:
                        self.SendPackets()
                else:
                    if args.pps != None:
                        self.SendPackets(pps=args.pps,Verbose = 0)
                    else:
                        self.SendPackets(Verbose = 0)


if __name__ == '__main__':
    main()
