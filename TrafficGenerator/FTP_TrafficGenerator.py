import logging

import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


from ScapyPacketGenerator import *



def main():
    #lets start with everything randomized
    RLENGTH = 1000
    TYPE = 'IPv4'

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="set replay interface", required=False,default='eth2' )
    parser.add_argument("-s", "--src", help="specify src ip", required=False, default=GenerateRandomIp())
    parser.add_argument("-d", "--dst", help="specify dst ip", required=False, default=GenerateRandomIp() )
    parser.add_argument("-S", "--sport", help="specify src port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-D", "--dport", help="specify dst port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-c", "--csport", help="specify src port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-C", "--cdport", help="specify dst port", required=False, default=21)
    parser.add_argument("-m", "--srcmac", help="specify src mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-M", "--dstmac", help="specify dst mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-X", "--method", help="specify method", required=False, default=4)
    parser.add_argument("-F", "--file", help="specify file to transfer", required=False, action='append',
                        default=['none'])

    #parser.add_argument("-F", "--file", help="specify file to transfer", required=False, action='append', default = ['/opt/TrafficGen/TestFiles/Malicious_DOC.doc'])
    parser.add_argument("-L", "--directory", help="spedify directory to transfer", required=False, default=None)
    parser.add_argument("-t", "--ftptype", help="specify time for continuous thression", required=False, default='I')
    parser.add_argument("-B", "--dstipv6", help="dst ipv6", required=False, default = None)
    parser.add_argument("-b", "--srcipv6", help="src ipv6", required=False, default = None)
    parser.add_argument("-A", "--setipv6", help="specify ipv6 transfer", required=False, default=False, action="store_true")
    parser.add_argument("-o", "--scapyoutput", help="specify output file", required=False, default=True, action="store_false")
    parser.add_argument("-a", "--active", help="specify active data transfer", required=False, default=True, action="store_false")
    parser.add_argument("-u", "--userpass", help="specify user and password", required=False,default='root:password' )
    parser.add_argument("-z", "--segments", help="segmentation", required=False, default=1)
    parser.add_argument("-q", "--clientseq", help="specify starting client SEQ", required=False, default = 1)
    parser.add_argument("-Q", "--serverseq", help="specify starting server SEQ", required=False, default = 1)
    parser.add_argument("-v","--vlanTag", help="specify vlan tag id", required=False, default=None)
    parser.add_argument("-P", "--dpchange", help="dataport no change", required=False, default=False, action="store_false")
    parser.add_argument("-l", "--pipeline", help="specify pipeline test", required=False, default=False, action="store_true")
    parser.add_argument("-x", "--pps", help="specify speed of replay in packets per second", required=False, default=None)
    parser.add_argument("-w", "--serverdir", help="specify server dir", required=False, default='/')
    parser.add_argument("-W", "--workingdir", help="specify working dir", required=False, default='/cwd')
    parser.add_argument("--gretunnel", help="encapsulate with gretunnel", required=False, default=False, action="store_true")



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

    #print SIPS
    #print DIPS

    FILE = []
    # Set Files to send
    if args.directory != None:
        FILE = set_files_list(args.directory)
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
                # lets strip the default if needed
    if len(FILE) > 1:
        # FILE.remove('/opt/TrafficGen/TestFiles/Malicious_DOC.doc')
        FILE.remove('none')

    # Set username password
    FTPUSER, FTPPASSWORD = args.userpass.strip('\n').split(':')


    if int(args.method) == 4:
        METHOD = 'GET'
    elif int(args.method) == 5:
        METHOD = 'PUT'
    elif int(args.method) == 6:
        METHOD = 'APPEND'
    else:
        raise Exception('this module only supports FTP')
    
                                   
    
    assert len(FILE) > 0, 'no files'
    if IPV6TEST:
        self = ''
        self = ScapyPacketGenerator()
        self.FTP.SetVariables(METHOD = METHOD,
                         dmac = args.dstmac,
                         smac = args.srcmac,
                         TYPE= TYPE,
                         src = None,
                         dst = None,
                         srcv6 = args.srcipv6,
                         dstv6 = args.dstipv6,
                         csport = int(args.csport),
                         cdport = int(args.cdport),
                         ddport = int(args.dport),
                         dsport = int(args.sport),
                         ftpuser = FTPUSER,
                         ftppassword = FTPPASSWORD,
                         ServerDir = args.serverdir,
                         CWD = args.workingdir,
                         Passive = args.active,
                         FTPTYPE = args.ftptype,  #???
                         FILES = FILE,
                         InitClientSeq = int(args.clientseq),
                         InitServerSeq = int(args.serverseq),
                         rlength = RLENGTH,
                         INTF = args.interface,
                         SEGMENTS = int(args.segments),
                         vlanTag=args.vlanTag)

        self.SetupInterface(INTF = args.interface)

        if len(FILE) == 1:
            if int(args.segments) == 1:
                print 'creating ftp packets'
                print 'is passive', args.active
                PACKETS = self.FTP.FTP_TEST()
            else:
                print 'creating ftp segmentation'
                PACKETS = self.FTP.FTP_SEGMENTATION_TEST()


        else:
            if args.dpchange == True:
                PACKETS = self.FTP.FTP_MGET_TEST()
            else:
                PACKETS = self.FTP.FTP_MGET_SAMEDPTEST()

            print 'strarting to support mulitiple files not supported yet for FTP'
        self.Packets = PACKETS
        if args.gretunnel:
            self.EncasulateGre()
        if args.scapyoutput:
            sendp(iface = args.interface)
        else:
            sendp(iface = args.interface,
                  verbose = 0,
                  )
    else:
        for SIP in SIPS:
            for DIP in DIPS:
                self = ''
                self = ScapyPacketGenerator()
                self.FTP.SetVariables(METHOD = METHOD,
                                 dmac = args.dstmac,
                                 smac = args.srcmac,
                                 TYPE= TYPE,
                                 src = args.src,
                                 dst = args.dst,
                                 srcv6 = None,
                                 dstv6 = None,
                                 csport = int(args.csport),
                                 cdport = int(args.cdport),
                                 ddport = int(args.dport),
                                 dsport = int(args.sport),
                                 ftpuser = FTPUSER,
                                 ftppassword = FTPPASSWORD,
                                 ServerDir = args.serverdir,
                                 CWD = args.workingdir,
                                 Passive = args.active,
                                 FTPTYPE = args.ftptype,  #???
                                 FILES = FILE,
                                 InitClientSeq = int(args.clientseq),
                                 InitServerSeq = int(args.serverseq),
                                 rlength = RLENGTH,
                                 INTF = args.interface,
                                 SEGMENTS = int(args.segments),
                                 vlanTag=args.vlanTag)

                self.SetupInterface(INTF = args.interface)

                if len(FILE) == 1:
                    if int(args.segments) == 1:
                        print 'creating ftp packets'
                        PACKETS = self.FTP.FTP_TEST()
                    else:
                        print 'creating ftp segmentation'
                        PACKETS = self.FTP.FTP_SEGMENTATION_TEST()


                else:
                    if args.dpchange == True:
                        PACKETS = self.FTP.FTP_MGET_TEST()
                    else:
                        PACKETS = self.FTP.FTP_MGET_SAMEDPTEST()

                    print 'strarting to support mulitiple files not supported yet for FTP'
                self.Packets = PACKETS
                if args.gretunnel:
                    self.EncasulateGre()
                if args.scapyoutput:
                    sendp(self.Packets,
                          iface = args.interface)
                else:
                    sendp(self.Packets,
                          iface = args.interface,
                          verbose = 0,
                          )

if __name__ == '__main__':
    main()

