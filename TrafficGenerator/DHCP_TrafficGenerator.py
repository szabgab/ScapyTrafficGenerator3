import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from support.Scapy_Control import *
import sys, getopt

def  mac_to_boot_chaddr(mac):
    chaddr = ''
    for item in mac.split(':'):
        integervalue =  int(item,16)
        ascii = chr(integervalue)
        chaddr += ascii
    #should create only 6 len, need 10
    chaddr += "\x00"*10
    return chaddr

class DHCP_Support():
    def __init__(self):
        self.Packets = []

    def DHCPTraffic( self,
                     dmac = '11:22:33:44:55:66',
                     smac = '22:33:44:55:66:77',
                     SIP = '1.1.1.1',
                     DIP = '2.2.2.2',
                     SUBNET = '255.255.255.0',
                     route = '2.2.2.1',
                     NameServer = '2.2.2.2',
                     leasetime = '600',
                     domain = 'Test.Local',
                    dport = 68,
                    sport = 67,
                    Inform = False,
                     Hostname = 'TestHost'):

        #form Request packet
        if Inform == True:
            INFORMPACKET = Ether(dst='ff:ff:ff:ff:ff:ff', src=smac, type=0x0800)\
                           / IP(src=SIP, dst='255.255.255.255')\
                           / UDP(dport=dport,sport=sport)\
                           / BOOTP(op=1,ciaddr=SIP,chaddr=mac_to_boot_chaddr(smac))\
                           / DHCP(options=[('message-type','inform'), ('end')])

            self.Packets.append(INFORMPACKET)
        
            ACKPACKET = Ether(src=dmac, dst=smac, type=0x0800) / IP(src=DIP, dst='255.255.255.255') / UDP(dport=sport,sport=dport) / BOOTP(op=2, chaddr=mac_to_boot_chaddr(smac), ciaddr=SIP, giaddr=DIP) / DHCP(options=[('message-type','ack'),
                                                                                                                                                                                                ('server_id', DIP),
                                                                                                                                                                                                ('lease_time', 600),
                                                                                                                                                                                                #('subnet_mask',SUBNET),
                                                                                                                                                                                                ('domain', domain), #\x00
                                                                                                                                                                                                ('router', route),
                                                                                                                                                                                                ('name_server', NameServer),
                                                                                                                                                                                                ('hostname', Hostname),
                                                                                                                                                                                                ('end')])
        
            self.Packets.append(ACKPACKET)
        else:
            DISCOVERPACKET = Ether(dst='ff:ff:ff:ff:ff:ff', type=0x0800) \
                             / IP(src='0.0.0.0', dst='255.255.255.255') \
                             / UDP(dport=dport,sport=sport) \
                             / BOOTP(op=1,chaddr=mac_to_boot_chaddr(smac)) \
                             / DHCP(options=[('message-type','discover'), ('end')])

            self.Packets.append(DISCOVERPACKET)
        
            DHCPOFFER = Ether(src=dmac, dst=smac, type=0x0800) / IP(src=DIP, dst=SIP) / UDP(dport=sport,sport=dport) / BOOTP(op=2, chaddr=mac_to_boot_chaddr(smac), yiaddr=SIP) / DHCP(options=[('message-type','offer'),
                                                                                                                                                                      ('server_id', DIP),
                                                                                                                                                                      ('lease_time', 600),
                                                                                                                                                                      ('hostname', Hostname),
                                                                                                                                                                      #('subnet_mask',leasetime),
                                                                                                                                                                      ('domain', domain), #\x00
                                                                                                                                                                      ('router', route),
                                                                                                                                                                      ('name_server', NameServer),
                                                                                                                                                                      ('end')])
        
            self.Packets.append(DHCPOFFER)
        

           
def main(argv):
    #lets start with everything randomized
    DSP = 67
    DDP = 68
    SIP = GenerateRandomIp()
    DIP = GenerateRandomIp()
    INTF = "wlp2s0"
    SMAC = GenerateRandomMac()
    DMAC = GenerateRandomMac()
    SUBNET = '255.255.255.0'
    route = '2.2.2.1'
    NameServer = '2.2.2.2'
    leasetime = '600'
    domain = 'tts.local'
    Inform = False
    scapyoutput = True
    Hostname = "hostname"
    #namearray = 'test.net:blablabla.com:1.2.3.4'
    try:
        opts, args = getopt.getopt(argv, 'i:s:d:S:D:m:M:I:u:r:N:l:n:h:fx"',['interface=',
                                                                         'src-ip=',
                                                                         'dst-ip=',
                                                                         'dsp=',
                                                                         'ddp=',
                                                                         'smac=',
                                                                         'dmac=',
                                                                         'subnet=',
                                                                       'route=',
                                                                       'Nameserver=',
                                                                       'leasetime=',
                                                                            'host='
                                                                       'domain',
                                                                         'inform',
                                                                          'scapyoutput'
                                                                       ],
                                   )
        
    except getopt.GetoptError:
        print 'failed to run error'

    
    for opt, arg in opts:
        if opt == '-i':
            INTF = arg.strip('\n')
            print 'set intf to' , INTF
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
        if opt == '-u':
            SUBNET = arg.strip('\n')
        if opt == '-r':
            route = arg.strip('\n')
        if opt == '-N':
            NameServer = arg.strip('\n')
        if opt == '-l':
            leasetime = str(arg.strip('\n'))
        if opt == '-n':
            domain = arg.strip('\n')
        if opt == '-f':
            Inform = True
        if opt == '-x':
            scapyoutput = False
        if opt == '-h':
            Hostname = arg.strip('\n')
        

    self = DHCP_Support()
    self.DHCPTraffic(dmac = DMAC,
                     smac = SMAC,
                     SIP = SIP,
                     DIP = DIP,
                     SUBNET = SUBNET,
                     route = route,
                     NameServer = NameServer,
                     leasetime = leasetime,
                     domain = domain,
                     dport = DDP,
                     sport = DSP,
                     Inform = Inform,
                     Hostname = Hostname)
    assert INTF != None, 'must define INTF'
    if scapyoutput == True:
        sendp(self.Packets, iface =INTF)
    else:
        sendp(self.Packets, iface =INTF,verbose = 0)



if __name__ == '__main__':
    main(sys.argv[1:])

    '''
    self = DHCP_Support()
    self.INTF = 'wlp2s0'
    self.DHCPTraffic(dmac = "22:22:22:22:22:22",
                     smac = "22:22:22:22:22:23",
                     SIP = '1.1.1.1',
                     DIP = "1.1.1.2",
                     SUBNET = "255.255.255.0",
                     route = "1.1.1.3",
                     NameServer = "1.1.1.4",
                     leasetime = 600,
                     domain = "mydom.com",
                     Hostname = "blablabla")
    wrpcap('DHCPSAMPLE.pcap', self.Packets)

    '''
                   
                   
                   
