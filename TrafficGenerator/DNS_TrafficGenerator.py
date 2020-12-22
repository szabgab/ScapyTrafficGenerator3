#Custom Foo Protocol Packet
message =  'This is a test message'    


"""----------------------------------------------------------------"""
""" Do not edit below this line unless you know what you are doing """
"""----------------------------------------------------------------"""
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from support.Scapy_Control import *

import getopt
#import os


from ScapyPacketGenerator import *

MTU = 1500
    
def main(argv):
    #lets start with everything randomized
    DSP = RandomSafePortGenerator()
    DDP = 53
    SIP = GenerateRandomIp()
    DIP = GenerateRandomIp()
    INTF = None
    SMAC = GenerateRandomMac()
    DMAC = GenerateRandomMac()
    ID = RandomSafePortGenerator()
    namearray = ['test.net','1.2.3.4']
    scapyoutput = True
    #namearray = 'test.net:blablabla.com:1.2.3.4'
    try:
        opts, args = getopt.getopt(argv, 'i:s:d:S:D:m:M:I:N:x"',['interface=',
                                                            'src-ip=',
                                                            'dst-ip=',
                                                            'dsp=',
                                                            'ddp=',
                                                            'smac=',
                                                            'dmac=',
                                                            'ID=',
                                                            'namearray=',
                                                                 'noscapyoutput',
                                                             
                                                            ],
                                   )
        
    except getopt.GetoptError:
        print 'failed to run error'

    
    for opt, arg in opts:
        if opt == '-i':
            INTF = arg.strip('\n')
        if opt == '-s':
            SIP = arg.strip('\n')
        if opt == '-d':
            DIP = arg.strip('\n')
        if opt == '-S':
            DSP = int(arg.strip('\n'))
        if opt == '-D':
            DDP = int(arg.strip('\n'))
        if opt == '-m':
            SMAC = arg.strip('\n')
        if opt == '-M':
            DMAC = arg.strip('\n')
        if opt == '-I':
            ID = int(arg.strip('\n'))
        if opt == '-N':
            namearray = arg.strip('\n').split(':')
            if len(namearray) > 2:
                print 'currently does not support chained'
                print 'this will result in dns malformed packet'
        if opt == '-x':
            scapyoutput = False
        
        
    self = ScapyPacketGenerator()
    self.SetupInterface(INTF = INTF)
    self.DNS.dnsTraffic( dmac = DMAC,
                         smac = SMAC,
                         src = SIP,
                         dst = DIP,
                         dport = DDP,
                         sport = DSP,
                         ID = ID,
                         namearray = namearray,
                         )
    
    self.Packets = self.DNS.Packets
    if scapyoutput == True:
        self.SendPackets()
    else:
        self.SendPackets(Verbose=0)
    
if __name__ == '__main__':
    main(sys.argv[1:])

