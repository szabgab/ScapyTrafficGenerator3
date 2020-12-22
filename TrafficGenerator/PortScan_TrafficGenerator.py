import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import getopt, sys
from support.ATTACK_Support import *

class ScapyPacketGenerator():
    def __init__(self):
        self.INTF = None
        self.Packets = []
        self.ATTACK = ATTACK_Support()
        
    def SetupInterface(self,
                       INTF = None,
                       ):
        self.INTF= INTF
        
    def SendPackets(self,Verbose = None):
        if Verbose == None: #dont set verbose
            sendp(self.Packets,iface=self.INTF)
        else:
            assert type(Verbose) == int, 'Verbose must be defined as integer'
            sendpfast(self.Packets,iface=self.INTF,pps=Verbose)


def main(argv):
    syncattempts = 5
    attempts = 2
    NetworkUnderAttack = None
    randomrangestart = RandomSafePortGenerator()
    randomrangestart2 = RandomSafePortGenerator()
    portRangeStart = randomrangestart -1
    portRangeStop = randomrangestart
    sportRangeStart = randomrangestart2 -1
    sportRangeStop = randomrangestart2
    
    SIP = GenerateRandomIp()
    SIPS = []
    SIPS.append(SIP)
    SMAC = GenerateRandomMac()
    DMAC = GenerateRandomMac()
    NetworkUnderAttack = None
    UDP = False
    try:
        opts, args = getopt.getopt(argv, 'i:s:d:m:M:p:P:A:U"',['interface=',
                                                           'src-ip=',
                                                           'dst-ip=',
                                                           'smac=',
                                                           'dmac=',
                                                           'portstart=',
                                                           'portend=',

                                                           'ATTEMPTS=',
                                                             'UDP',
                                                           ])
        
    
    except getopt.GetoptError:
        print 'failed to run error', getopt.GetoptError

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
            
            NetworkUnderAttack = arg.strip('\n')  #this is a network ex: 1.1.1.1/24
            if '/' in NetworkUnderAttack:
                pass
            else:
                NetworkUnderAttack += '/32'
        if opt == '-m':
            SMAC = arg.strip('\n')
        if opt == '-M':
            DMAC = arg.strip('\n')  
        if opt == '-p':
            sportRange = str(arg.strip('\n'))
            #print 'sportRange', sportRange
            sportRangeStart, sportRangeStop = sportRange.split(':')
            sportRangeStart = int(sportRangeStart)
            sportRangeStop = int(sportRangeStop)+ 1
        if opt == '-P':
            portRange = str(arg.strip('\n'))
            #print 'portRange', portRange
            portRangeStart, portRangeStop = portRange.split(':')
            portRangeStart = int(portRangeStart)
            portRangeStop = int(portRangeStop) + 1
        if opt == '-U':
            UDP = True
        if opt == '-A':
            syncattempts = int(arg.strip('\n'))
            attempts = int(arg.strip('\n'))

    assert INTF != None, 'must define interface with -i'
    for SIP in SIPS:
        self = ''
        self = ScapyPacketGenerator()
        self.ATTACK.SetVariables(dmac = DMAC,
                                 smac = SMAC,
                                 src = SIP,
                                 INTF = INTF)
        if UDP == False:
            print 'tcp'
            self.ATTACK.TCP_PORT_SCAN(syncattempts = syncattempts,
                                  portRangeStart=portRangeStart,
                                  portRangeStop=portRangeStop,
                                  sportRangeStart =sportRangeStart,
                                  sportRangeStop =sportRangeStop,
                                  NetworkUnderAttack=NetworkUnderAttack,
                                  Types=[3])
        else:
            print 'udp'
            self.ATTACK.UDP_PORT_SCAN(attempts = attempts,
                                  portRangeStart=portRangeStart,
                                  portRangeStop=portRangeStop,
                                  sportRangeStart =sportRangeStart,
                                  sportRangeStop =sportRangeStop,
                                  NetworkUnderAttack=NetworkUnderAttack)
    

    
if __name__ == '__main__':
    main(sys.argv[1:])
                               

            
        
