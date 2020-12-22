import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import getopt
from support.SMTP_Support import *
from ScapyPacketGenerator import *

MTU = 1500


def main(argv):
    #initiate class
    self = ScapyPacketGenerator()

    #declare default values
    SP = RandomSafePortGenerator()
    DP = 25
    INTF = None
    SMAC = GenerateRandomMac()
    DMAC = GenerateRandomMac()
    SIP = GenerateRandomIp()
    DIP = GenerateRandomIp()
    userName = 'userName'
    serverName = 'serverName'
    password = 'password'
    TO = 'SendMailTo@test.com'
    FROM ='SendMailFrom@Test.com'
    DIPS = []
    DIPS.append(DIP)
    SIPS = []
    SIPS.append(SIP)

    try:
        opts, args = getopt.getopt(argv, 'i:s:d:S:D:m:M:n:N:p:T:F"',['interface=',
                                                                 'src-ip=',
                                                                 'dst-ip=',
                                                                 'dp=',
                                                                 'sp=',
                                                                 'smac=',
                                                                 'dmac=',
                                                                 'userName=',
                                                                 'serverName=',
                                                                 'password=',
                                                                 "TO=",
                                                                 "FROM=",
                                   ],
                                   )

    except getopt.GetoptError:
        print 'failed to run error'

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
        if opt == '-S':
            SP = int(arg.strip('\n'))
        if opt == '-D':
            DP = int(arg.strip('\n'))
        if opt == '-m':
            SMAC = arg.strip('\n')
        if opt == '-M':
            DMAC = arg.strip('\n')
        if opt == '-F':
            FROM = arg.strip('\n')
        if opt == '-T':
            TO = arg.strip('\n')
        if opt == '-n':
            userName =arg.strip('\n')
        if opt == '-N':
            serverName =arg.strip('\n')
        if opt == '-p':
            password = arg.strip('\n')

    self.INTF = INTF
    assert self.INTF != None, 'please specify interface'

    for SIP in SIPS:
        for DIP in DIPS:
            self.SMTP.SetVariables(dmac = DMAC,
                                   smac = SMAC,
                                   TYPE= 'IPv4',
                                   src = SIP,
                                   dst = DIP,
                                   sport = SP,
                                   dport = DP,
                                   username = userName,
                                   password = password,
                                   ServerName = serverName,
                                   TO=TO,
                                   FROM = FROM,
                                   )
            self.Packets = self.SMTP.SMTP_CONNECT_NOATTACHMENT()
            self.SendPackets()


if __name__ == '__main__':
    main(sys.argv[1:])
