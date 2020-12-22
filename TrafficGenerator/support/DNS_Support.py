import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class DNS_Support():
    def __init__(self):
        self.Packets = []
        
    def SetupEther(self,
                   dmac = None,
                   smac = None,
                   TYPE = None,
                   ):
        self.Ether = Ether()
        if dmac != None:
            self.Ether.dst = dmac
        if smac != None:
            self.Ether.src = smac
        #print 'ether set', self.Ether.display
    def SetupIp(self,
                version = None,
                ihl = None,
                tos = None,
                LEN = None,
                flags = None,
                frag = None,
                ttl = None,
                proto = None,
                chksum = None,
                src = None,
                dst = None,
                options = None,
                ):
        self.IP = IP()
        if version != None:
            self.IP.version = version
        if ihl != None:
            self.IP.ihl = ihl
        if LEN != None:
            self.IP.len = LEN
        if flags != None:
            self.IP.flags = flags
        if frag != None:
            self.IP.frag = frag
        if ttl != None:
            self.IP.ttl = ttl
        if proto != None:
            self.IP.proto = proto
        if chksum != None:
            self.IP.chksum = chksum
        if src != None:
            self.IP.src = src
            self.ORIGINALSRC = src
        if dst != None:
            self.IP.dst = dst
        #to do options --> not sure what is does now
        #print 'ip set', self.IP.display()
    def SetupUDP(self,
                 sport= None,
                 dport= None,
                 chksum= None,
                 ):
        self.UDP = UDP()
        if sport != None:
            self.UDP.sport = sport
        if dport != None:
            self.UDP.dport = dport
        if chksum != None:
            self.UDP.chksum = chksum
            
     
    def SetDNS(self,
               ID = None,
               ancount = None,
               ):
        self.DNS = DNS()
        if ID != None:
            self.DNS.id = ID
        if ancount != None:
            self.DNS.ancount = ancount

    def SetDNSQR (self,
                  qname = None,
                  ):
        self.DNSQR = DNSQR()
        if qname != None:
            self.DNSQR.qname = qname

    def SetDNSRR (self,
                  name = [],  #['dnsname','ipaddr']
                  chain = False,
                  TYPE = 'CNAME',
                  ):
        assert (len(name)) == 2, 'name format not correct'
        if name != None:
            self.DNSRR = DNSRR()
            self.DNSRR.rrname = name[0]
            self.DNSRR.rdata = name[1]
            self.DNSRR.ttl=1000
            if chain == True:
                self.DNSRR.type = TYPE
    def SwapSrc_Dst(self):
        sport = self.UDP.sport
        dport = self.UDP.dport
        sip = self.IP.src
        dip = self.IP.dst
        smac = self.Ether.src
        dmac = self.Ether.dst
        self.UDP.sport = dport
        self.UDP.dport = sport
        self.IP.dst = sip
        self.IP.src = dip
        self.Ether.src = dmac
        self.Ether.dst = smac
        
                
    def dnsTraffic( self,
                    dmac = '11:22:33:44:55:66',
                    smac = '22:33:44:55:66:77',
                    src = '1.1.1.1',
                    dst = '2.2.2.2',
                    dport = 53,
                    sport = 6666,
                    ID = 1111,
                    namearray = ['test.net','1.2.3.4'],
                    ):

        assert len(namearray) == 2, 'currently no support for chain names'
        
        self.SetupEther(dmac = dmac,
                        smac = smac,
                        )
        self.SetupIp(src = src,
                     dst = dst,
                     )
        self.SetupUDP(sport= sport,
                      dport= dport,
                      )
        self.SetDNS(ID = ID,
                      )
        self.SetDNSQR(qname = namearray[0],
                      )

        #send request
        self.DNS.qd = self.DNSQR
        self.DNS.rd = 1
        packet = self.Ether/self.IP/self.UDP/self.DNS
        packet[IP].len = len(packet[IP])
        packet[UDP].len = len(packet[UDP])
        del packet[IP].chksum
        del packet[UDP].chksum
        self.Packets.append(packet)
        
        self.SetDNSRR(name = [namearray[0],namearray[1]],
                      )
        
        #send responce
        self.SwapSrc_Dst()
        
        self.DNS.an = self.DNSRR
        self.DNS.ancount = 1 #number of chains 1 for no chain
        self.DNS.ra = 1
        self.DNS.qr = 1
        packet = self.Ether/self.IP/self.UDP/self.DNS
        packet[IP].len = len(packet[IP])
        packet[UDP].len = len(packet[UDP])
        del packet[IP].chksum
        del packet[UDP].chksum
        self.Packets.append(packet)
                        
        
def test():
    self = DNS_Support()
    self.dnsTraffic()
    sendp(self.Packets, iface = 'wlan0')

        
           
                    
                    
                    
                    
            
                   
                   
                   
