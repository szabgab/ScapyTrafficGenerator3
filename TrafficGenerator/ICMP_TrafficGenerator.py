import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from support.Scapy_Control import *
import sys, getopt

class ICMP_Support():
    def __init__(self):
        self.Packets = []
                
    def ICMPTraffic( self,
                     dmac = '11:22:33:44:55:66',
                     smac = '22:33:44:55:66:77',
                     SIP = '1.1.1.1',
                     DIP = '2.2.2.2',
                     DSTReply = True,
                     pingSize = 64,
                     retries = 0,
                     ):
        #request
        packets = []
        remainingbytes=pingSize
        while remainingbytes != 0:
            if remainingbytes > 500:
                loadsize = 500
                remainingbytes -= 500
                LOAD = RamdomRawData(size=loadsize)
                #print 'loaddata', LOAD
                requestPacket= Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP, proto='icmp') /ICMP(type='echo-request')/ Raw(load=LOAD)
                packets.append(requestPacket)
                for i in range(retries):
                    LOAD = RamdomRawData(size=loadsize)
                    #print 'loaddata retry', LOAD
                    requestPacket= Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP, proto='icmp') /ICMP(type='echo-request',seq = requestPacket.seq +1)/ Raw(load=LOAD)
                    packets.append(requestPacket)

                if DSTReply == True:
                    responsePacket = Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP, proto='icmp') /ICMP(type='echo-reply')/ Raw(load=LOAD)
                    packets.append(responsePacket)
            else:
                loadsize = remainingbytes
                remainingbytes = 0
                LOAD = RamdomRawData(size=loadsize)
                #print 'loaddata', LOAD
                requestPacket= Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP, proto='icmp') /ICMP(type='echo-request')/ Raw(load=LOAD)
                packets.append(requestPacket)
                for i in range(retries):
                    LOAD = RamdomRawData(size=loadsize)
                    #print 'loaddata retry', LOAD
                    requestPacket= Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP, proto='icmp') /ICMP(type='echo-request',seq = requestPacket.seq +1)/ Raw(load=LOAD)
                    packets.append(requestPacket)

                if DSTReply == True:
                    #print 'reply'
                    responsePacket = Ether(dst=dmac, src=smac, type=0x0800) / IP(src=SIP, dst=DIP, proto='icmp') /ICMP(type='echo-reply')/ Raw(load=LOAD)
                    packets.append(responsePacket)
            
            
        return packets
        

        
       
        

           
def main(argv):
    #lets start with everything randomized
    SIP = GenerateRandomIp()
    DIP = GenerateRandomIp()
    INTF = None
    SMAC = GenerateRandomMac()
    DMAC = GenerateRandomMac()
    scapyoutput = True
    Respond = True
    SIZE = 64
    retries = 0
    loop = 1
    try:
        opts, args = getopt.getopt(argv, 'i:s:d:m:M:S:r:L:R"',['interface=',
                                                                         'src-ip=',
                                                                         'dst-ip=',
                                                                         'dsp=',
                                                                         'ddp=',
                                                                         'smac=',
                                                                         'dmac=',
                                                                         'size=',
                                                                       'retries=',
                                                                       ],
                                   )
        
    except getopt.GetoptError:
        print 'failed to run error'

    SIPS = [SIP]
    DIPS = [DIP]
    for opt, arg in opts:
        if opt == '-i':
            INTF = arg.strip('\n')
            print 'set intf to' , INTF
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
        if opt == '-m':
            SMAC = arg.strip('\n')
        if opt == '-M':
            DMAC = arg.strip('\n')                 
        if opt == '-S':
            SIZE = int(arg.strip('\n'))
        if opt == '-r':
            retries = int(arg.strip('\n'))
        if opt == '-R':
            Respond = False
        if opt == '-L':
            loop = int(arg.strip('\n'))
        

    self = ICMP_Support()
    if len(SIPS) > 1:
        for SIP in SIPS:
            SMAC = GenerateRandomMac()
            for DIP in DIPS:
                if len(DIPS) > 1:
                    DMAC = GenerateRandomMac()
                for l in range(loop):
                    packets = self.ICMPTraffic(dmac = DMAC,
                                     smac = SMAC,
                                     SIP = SIP,
                                     DIP = DIP,
                                     DSTReply = Respond,
                                     pingSize = SIZE,
                                     retries = retries,
                                               )

                    assert INTF != None, 'must define INTF'
                    if scapyoutput == True:
                        sendp(packets, iface =INTF)
                    else:
                        sendp(packets, iface =INTF,verbose = 0)
    else:
        packets = self.ICMPTraffic(dmac=DMAC,
                                   smac=SMAC,
                                   SIP=SIPS[0],
                                   DIP=DIPS[0],
                                   DSTReply=Respond,
                                   pingSize=SIZE,
                                   retries=retries,
                                   )
        assert INTF != None, 'must define INTF'
        if scapyoutput == True:
            sendp(packets, iface=INTF)
        else:
            sendp(packets, iface=INTF, verbose=0)


if __name__ == '__main__':
    main(sys.argv[1:])

    
                    
            
                   
                   
                   
