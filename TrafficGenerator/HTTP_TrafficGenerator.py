import logging

import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ScapyPacketGenerator import *

def main():
    #SET ALL DEFAULT VALUES
    RLENGTH = 1000

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="set replay interface", required=False,default='eth2' )
    parser.add_argument("-r", "--syncattack", help="specify sync attack attempt", required=False, default=False)
    parser.add_argument("-s", "--src", help="specify src ip", required=False, default=GenerateRandomIp())
    parser.add_argument("-d", "--dst", help="specify dst ip", required=False, default=GenerateRandomIp() )
    parser.add_argument("-S", "--sport", help="specify src port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-D", "--dport", help="specify dst port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-m", "--srcmac", help="specify src mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-M", "--dstmac", help="specify dst mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-X", "--method", help="specify method", required=False, default=1)
    parser.add_argument("-E", "--encoding", help="specify encoding", required=False, default=1)
    #parser.add_argument("-F", "--file", help="specify file to transfer", required=False, action='append', default = ['/opt/TrafficGen/TestFiles/Malicious_DOC.doc'])
    parser.add_argument("-F", "--file", help="specify file to transfer", required=False, action='append',default=['none'])

    parser.add_argument("--host", help="specify host", required=False, default='testhost.net')

    parser.add_argument("-H", "--chunk", help="specify chuncked size. only applicable is -E is 2 or 4", required=False, default=200)
    parser.add_argument("-t", "--type", help="specify type", required=False, default='IPv4')
    parser.add_argument("-T", "--time", help="specify time for continuous thression", required=False, default=False)
    parser.add_argument("-U", "--useragent", help="specify user-agent", required=False, default='curl/7.35.0')
    parser.add_argument("-V", "--version", help="specify http version", required=False, default='HTTP/1.1')
    parser.add_argument("-R", "--response", help="specify server response", required=False, default='HTTP/1.1 200 OK')
    parser.add_argument("-N", "--name", help="specify server name", required=False,default='Nathans Super Awesome Server 1.0')
    parser.add_argument("-u", "--url", help="specify url", required=False, default='/testurl')
    parser.add_argument("-q", "--clientseq", help="specify starting client SEQ", required=False, default = 1)
    parser.add_argument("-Q", "--serverseq", help="specify starting server SEQ", required=False, default = 1)
    parser.add_argument("-L", "--directory", help="spedify directory to transfer", required=False, default=None)
    parser.add_argument("-B", "--dstipv6", help="dst ipv6", required=False, default = None)
    parser.add_argument("-b", "--srcipv6", help="src ipv6", required=False, default = None)
    parser.add_argument("--gretunnel", help="encapsulate with gretunnel", required=False, default=False, action="store_true")
    parser.add_argument("-A", "--setipv6", help="specify ipv6 transfer", required=False, default=False, action="store_true")
    parser.add_argument("-l", "--pipeline", help="specify pipeline test", required=False, default=False, action="store_true")
    parser.add_argument("-o", "--scapyoutput", help="specify output file", required=False, default=True, action="store_false")
    parser.add_argument("-x", "--pps", help="specify speed of replay in packets per second", required=False, default=None)
    parser.add_argument("-w", "--wait", help="specify a wait location", required=False, default=None)
    parser.add_argument("-j", "--requestheader", help="specify additional request", required=False,action='append', default=[])
    parser.add_argument("-k", "--responseheader", help="specify additional response", required=False,action='append', default=[])
    parser.add_argument("-y", "--vlanTagType", help="specify additional response", required=False, default=2048)
    parser.add_argument("-v","--vlanTag", help="specify vlan tag id", required=False, default=None)
    parser.add_argument("-c","--chain", help="redirect Chain", required=False,action='append', default=[])
    parser.add_argument("-e","--tls", help="encryption", required=False, default = None)
    parser.add_argument("-O", "--timeoffset", help="specify in seconds how long ago packet is", required=False, default=0)

    args = parser.parse_args()
    requestheaders = []
    responseheaders = []
    if args.requestheader != []:
        for r in args.requestheader:
            requestheaders.append(r)
        #print 'request headers are', requestheaders
    if args.responseheader != []:
        for r in args.responseheader:
            responseheaders.append(r)
        #print 'response headers are', args.requestheader
    INTF = str(args.interface)

    TIME = None
    syncattempts = 5
    requestattempts = 1
    NetworkUnderAttack = None
    randomized = False
    wait = 0
    DATAONLY = 0

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
    if len(FILE) > 1:
        #FILE.remove('/opt/TrafficGen/TestFiles/Malicious_DOC.doc')
        FILE.remove('none')

    # Set Wait
    if args.wait != None:
        waitlocation, wait = args.wait.strip('\n').split(':')
        waitlocation = str(waitlocation)
        wait = int(wait)





    #set sync attak
    if args.syncattack != False:
        SYNCATTACK = True
        c = args.syncattack.strip('\n').split(':')
        #print 'r command length', len(c)
        if len(c) == 2:
            syncattempts, requestattempts = c
        elif len(c) ==3:
            syncattempts, requestattempts, NetworkUnderAttack = c
        elif len(c) == 1:
            syncattempts = c[0]
        else:
            raise Exception('improperly formatted syncattack')
    else:
        SYNCATTACK = False

    # handle User Strings



    #handle received data

    GZIP = False
    CHUNKED = False
    DISPSITION = False
    #print 'method', int(Method)
    if int(args.method) == 1:
        METHOD = 'GET'
        if (int(args.encoding) == 2) or (int(args.encoding) == 4):
            CHUNKED = args.chunk
        if (int(args.encoding) == 3) or (int(args.encoding) == 4):
            GZIP = True
        if (int(args.encoding) == 5) or (int(args.encoding) == 6):
            print 'multi-part form data is not currently supported for http get'
            print 'switching to binary encoding'    
    elif int(args.method) == 2:
        METHOD = 'PUT'
        if (int(args.encoding) == 2) or (int(args.encoding) == 3) or (int(args.encoding) == 4):
            print 'this encoding is not supported for http put'
            print 'switching to binary encoding'
            Encoding = 1
        if (int(args.encoding) == 5) or (int(args.encoding) == 6):
            DISPSITION = True
    elif int(args.method) == 3:
        METHOD = 'POST'
        if (int(args.encoding) == 2) or (int(args.encoding) == 3) or (int(args.encoding) == 4):
            print 'this encoding is not supported for http put'
            print 'switching to binary encoding'
            Encoding = 1
        if (int(args.encoding) == 5) or (int(args.encoding) == 6):
            DISPSITION = True
    else:
        raise Exception('this module only supports ftp')


    if args.vlanTag != None:
        vlanTag= int(args.vlanTag)

        print 'attempting to set http traffic vlan to %s' %str(vlanTag)
    else:
        vlanTag = None

    if '302' in args.response:
        args.response = random.choice(['HTTP/1.1 302 Found', 'HTTP/1.1 302 Moved Temporarily'])
    if IPV6TEST == True:
        self = ''
        self = ScapyPacketGenerator()
        self.HTTP.SetVariables(METHOD = METHOD,
                               DISPSITION = DISPSITION, 
                               UserAgent = args.useragent,
                               dmac = args.dstmac,
                               smac = args.srcmac,
                               TYPE= args.type,
                               src = None,
                               dst = None,
                               srcv6 = SIPS[0],
                               dstv6 = DIPS[0],
                               sport = int(args.sport),
                               dport = int(args.dport),
                               INTF = args.interface,
                               FILES = FILE,
                               InitClientSeq=args.clientseq,
                               InitServerSeq=args.serverseq,
                               HTTPVERSION= args.version,
                               ServerResponce = args.response,
                               ServerName = args.name,
                               GZIP = GZIP,
                               CHUNKED = CHUNKED,
                               rlength = RLENGTH,
                               TIME=args.time,
                               Verbose = args.pps,
                               HOST = args.host,
                               URLBASE = args.url,
                               requestHeaders= args.requestheader,
                               responseHeaders= args.responseheader,
                               randomized = randomized,
                               DATAONLY = DATAONLY,
                               #vlanTag=vlanTag,
                               chain=args.chain,
                               ssl_tls=args.tls,
                               #vlanTagType=int(args.vlanttagtype)
                               timeoffset=args.timeoffset)
       
        self.SetupInterface(INTF = args.interface)
        if len(args.chain) > 0:
            self.Packets = self.HTTP.HTTP_REDIRECT_CHAIN()
            print 'number of packets in rdir2', len(self.Packets)
        else:
            if "302" in args.response:
                self.Packets = self.HTTP.HTTP_REDIRECT()
            else:
                if FILE[0].lower() == 'none':
                    print 'no file test'
                    PACKETS = self.HTTP.HTTP_NOFILE()
                    self.Packets += PACKETS

                if SYNCATTACK == True:
                    print 'network under attack', NetworkUnderAttack
                    self.HTTP.HTTP_SYNC_ATTACK(syncattempts = int(syncattempts),
                                               requestattempts = int(requestattempts),
                                               NetworkUnderAttack = NetworkUnderAttack,
                                               )
                    self.Packets += self.HTTP.Packets
                else:
                    if DISPSITION == True:
                        print 'multipart test'
                        self.HTTP.HTTP_MULTIPART_TEST()
                        self.Packets += self.HTTP.Packets
                    else:
                        print 'FILES are', FILE
                        if len(FILE) == 1:
                            if args.time == False:
                                print 'normal session'
                                self.HTTP.HTTP_TEST(DATAONLY=DATAONLY)
                                self.Packets += self.HTTP.Packets
                            else:
                                print 'continuous session'
                                self.HTTP.HTTP_CONTINUOUS_SESSION_TEST()
                        else:
                            if args.pipeline == True:
                                print 'creating http pipeline packets'
                                self.HTTP.HTTP_PIPELINE_TEST()
                                self.Packets += self.HTTP.Packets
                            else:
                                print 'http multi test'
                                #self.HTTP.HTTP_MULTI_TEST()
                                for F in FILE:
                                    self.HTTP.FILES=[F]
                                    self.HTTP.HTTP_TEST(DATAONLY=DATAONLY)
                                    self.Packets += self.HTTP.Packets

                if args.gretunnel:
                    print 'encapsulating with gre'
                    self.EncasulateGre()
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
        print 'SIPS', str(SIPS)
        print 'DIPS', str(DIPS)
        for SIP in SIPS:
            for DIP in DIPS:
                self = ''
                self = ScapyPacketGenerator()
                self.HTTP.SetVariables(METHOD = METHOD,
                                       DISPSITION = DISPSITION,
                                       UserAgent = args.useragent,
                                       dmac = args.dstmac,
                                       smac = args.srcmac,
                                       TYPE= args.type,
                                       src = SIP,
                                       dst = DIP,
                                       srcv6 = None,
                                       dstv6 = None,
                                       sport = args.sport,
                                       dport = args.dport,
                                       INTF = args.interface,
                                       FILES = FILE,
                                       InitClientSeq=args.clientseq,
                                       InitServerSeq=args.serverseq,
                                       HTTPVERSION= args.version,
                                       ServerResponce = args.response,
                                       ServerName = args.name,
                                       GZIP = GZIP,
                                       CHUNKED = CHUNKED,
                                       rlength = RLENGTH,
                                       TIME=args.time,
                                       Verbose = args.pps,
                                       HOST = args.host,
                                       URLBASE = args.url,
                                       requestHeaders= requestheaders,
                                       responseHeaders= responseheaders,
                                       randomized = randomized,
                                       DATAONLY = DATAONLY,
                                       #vlanTag=vlanTag,
                                       chain=args.chain,
                                       ssl_tls=args.tls,
                                       timeoffset=args.timeoffset)

                self.SetupInterface(INTF = INTF)
                if len(args.chain) > 0:
                    self.Packets = self.HTTP.HTTP_REDIRECT_CHAIN()
                else:
                    if wait > 0:
                        print 'http wait test'
                        self.Packets = self.HTTP.HTTP_WAIT_TEST(wait=wait,
                                                 waitlocation = waitlocation)
                    else:
                        if "302" in args.response:
                            PACKETS = self.HTTP.HTTP_REDIRECT()
                            self.Packets += PACKETS
                        else:
                            if FILE[0].lower() == 'none':
                                print 'no file test'
                                PACKETS = self.HTTP.HTTP_NOFILE()
                                self.Packets += PACKETS
                            else:
                                if SYNCATTACK == True:
                                    print 'network under attack', NetworkUnderAttack
                                    self.HTTP.HTTP_SYNC_ATTACK(syncattempts = int(syncattempts),
                                                               requestattempts = int(requestattempts),
                                                               NetworkUnderAttack = NetworkUnderAttack,
                                                               )

                                    self.Packets += self.HTTP.Packets
                                else:
                                    if DISPSITION == True:
                                        print  'http multipart test'
                                        self.HTTP.HTTP_MULTIPART_TEST()
                                        self.Packets += self.HTTP.Packets
                                    else:
                                        print  'files are',  FILE
                                        if len(FILE) == 1:
                                            if args.time == False:
                                                print 'normal session'
                                                self.HTTP.HTTP_TEST(DATAONLY=DATAONLY)
                                                self.Packets += self.HTTP.Packets
                                            else:
                                                print 'continuous session'
                                                self.HTTP.HTTP_CONTINUOUS_SESSION_TEST()
                                        else:
                                            if args.pipeline == True:
                                                print 'creating http pipeline packets'
                                                self.HTTP.HTTP_PIPELINE_TEST()
                                                self.Packets += self.HTTP.Packets
                                            else:
                                                print 'http multi test'
                                                self.HTTP.HTTP_MULTI_TEST()
                                                #for F in FILE:
                                                #    self.HTTP.FILES = [F]
                                                #    self.HTTP.HTTP_TEST(DATAONLY=DATAONLY)
                                                self.Packets += self.HTTP.Packets
                if args.gretunnel:
                    self.EncasulateGre()
                if args.vlanTag:
                    self.EncasulateVlan(vlanTag=int(args.vlanTag),
                                        vlanTagType=int(args.vlanTagType))
                if args.scapyoutput == True:
                    self.SendPackets()
                else:
                    self.SendPackets(Verbose = 0)





                


if __name__ == '__main__':
    main()

