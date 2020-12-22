
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import getopt

from ScapyPacketGenerator import *

MTU = 1500


def main(argv):
    #initiate class
    self = ScapyPacketGenerator()

    #declare default values
    SP = RandomSafePortGenerator()
    TELNETDP = 25
    SMBDP = 139
    RADIUSSP = 1645
    RADIUSDP = 1812
    TDSSP = 1999
    TDSDP = 1433
    SSHSP = 48641
    SSHDP = 22
    DIAMETERDP = 3868
    MAPIDP = 135
    MAPISP = 1066
    INTF = None
    SMAC = GenerateRandomMac()
    DMAC = GenerateRandomMac()
    SIP = GenerateRandomIp()
    DIP = GenerateRandomIp()
    userName = 'userName10'
    serverName = 'serverName'
    password = 'password'
    DP = None
    SP = None
    DIPS = []
    DIPS.append(DIP)
    SIPS = []
    SIPS.append(SIP)
    TYPE = 'telnet'
    hostname = 'hostname'
    try:
        opts, args = getopt.getopt(argv, 'i:s:d:S:D:m:M:n:N:p:T:h:o:"',['interface=',
                                                                 'src-ip=',
                                                                 'dst-ip=',
                                                                 'dp=',
                                                                 'sp=',
                                                                 'smac=',
                                                                 'dmac=',
                                                                 'userName=',
                                                                 'serverName=',
                                                                 'password=',
                                                                 "TYPE=",
                                                                 "hostname=",
                                                                        "originalsource="
                                   ],
                                   )

    except getopt.GetoptError as err:
        print 'failed 2 run error', str(err)

    for opt, arg in opts:
        if opt == '-i':
            INTF = arg.strip('\n')
        if opt == '-s':
            SIPS = []
            SIP = arg.strip('\n')
            #lets check to see if SIP is a network
            if '/' in SIP:
                SIP, Netmask = SIP.split('/')
                SIPS = GetIpsInNetwork(ip = SIP,
                                       netmask = Netmask)
            else:
                SIPS.append(SIP)
        if opt == '-o':
            originalSource=arg.strip('\n')
        if opt == '-d':
            DIPS = []
            DIP = arg.strip('\n')
            #lets check to see if DIP is a network
            if '/' in DIP:
                DIP, Netmask = DIP.split('/')
                DIPS = GetIpsInNetwork(ip = DIP,
                                       netmask = Netmask)
            else:
                DIPS.append(DIP)
        if opt == '-h':
            hostname = str(arg.strip('\n'))
        if opt == '-S':
            SP = int(arg.strip('\n'))
        if opt == '-D':
            DP = int(arg.strip('\n'))
        if opt == '-m':
            SMAC = arg.strip('\n')
        if opt == '-M':
            DMAC = arg.strip('\n')
        if opt == '-n':
            userName =arg.strip('\n')
        if opt == '-N':
            serverName =arg.strip('\n')
        if opt == '-p':
            password = arg.strip('\n')
        if opt == '-T':
            TYPE = str(arg.strip('\n')).lower()

    self.INTF = INTF
    assert self.INTF != None, 'please specify interface'

    for SIP in SIPS:
        for DIP in DIPS:
            if TYPE == 'ssh':
                print 'ssh traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or SSHSP,
                                   dport = DP or SSHDP,
                                   username = userName,
                                   )
                self.Packets = self.Template.SSHTest()
                print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'rsh':
                print 'rsh traffic'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 1023,
                                   dport = DP or 514,
                                   username = userName,
                                   servername = serverName,
                                   )
                self.Packets = self.Template.rshTest()
                print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'imap':
                print 'imap traffic'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 55032,
                                   dport = DP or 143,
                                   username = userName,
                                   )
                self.Packets = self.Template.imapTest()
                print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'pop3':
                print 'pop3 traffic'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 2058,
                                   dport = DP or 110,
                                   username = userName,
                                   )
                self.Packets = self.Template.Pop3Test()
                print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'krb':
                print 'krb traffic'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 44444,
                                   dport = DP or 88,
                                   username = userName,
                                   )
                self.Packets = self.Template.KRBTest()
                print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'radius':
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                print 'sending radius traffic'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or RADIUSSP,
                                   dport = DP or RADIUSDP,
                                   username = userName,
                                   )
                self.Packets = self.Template.RadiusTest()
                print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'mapi':
                print 'sending mapi traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or MAPISP,
                                   dport = DP or MAPIDP,
                                   username = userName,
                                   servername = serverName,
                                   )
                self.Packets = self.Template.MAPITest()
                self.SendPackets()
            if TYPE == 'telnet':
                print 'sending telnet traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 12345,
                                   dport = DP or TELNETDP,
                                   username = userName,
                                   password = password,
                                   servername = serverName,
                                   )
                self.Packets = self.Template.TelnetTest()
                self.SendPackets()
            if TYPE == 'tds':
                print 'sending tds traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or TDSSP,
                                   dport = DP or TDSDP,
                                   username = userName,
                                   hostname = hostname,
                                   servername = serverName,
                                   )
                self.Packets = self.Template.TDSTest()
                self.SendPackets()
            if TYPE == 'rlogin':
                print 'sending rlogin traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 3214,
                                   dport = DP or SMBDP,
                                   username = userName,
                                   hostname = hostname,
                                   servername = serverName,  #current implementation does nothing for server name
                                   )
                self.Packets = self.Template.RLOGINTest()
                #print len(self.Packets), 'packets'
                self.SendPackets()
            if TYPE == 'smb':
                print 'sending smb traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 3214,
                                   dport = DP or SMBDP,
                                   username = userName,
                                   )
                self.Packets = self.Template.SMBTest()
                print len(self.Packets), 'packets'

                self.SendPackets()
            if TYPE == 'diameter':
                print 'sending diameter traffic'
                if DP == None:
                    print 'NO DP'
                if SP == None:
                    print 'NO SP'
                self.Template.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP or 5443,
                                   dport = DP or DIAMETERDP,
                                   username = userName,
                                   password = password,
                                   servername = serverName,
                                   )
                self.Packets = self.Template.DiameterTest()
                print len(self.Packets), 'packets'

                self.SendPackets()
            else:
                assert os.path.exists(TYPE), 'if specific type is not specified, a pcap file must be given and %s does not exist' %TYPE
                self.Template.SetVariables(dmac=DMAC,
                                           smac=SMAC,
                                           TYPE='IPv4',
                                           src=SIP,
                                           dst=DIP,
                                           sport=SP,
                                           dport=DP,
                                           username=userName,
                                           )
                self.Packets = self.Template.AlterPacketsBasic(originalSource=originalSource,pcap=TYPE)
                print len(self.Packets), 'packets'

                self.SendPackets()

if __name__ == '__main__':
    main(sys.argv[1:])