from TCP_flow_control import *
from Scapy_Control import *
import os
from time import sleep
import random

class ATTACK_Support():
    def __init__(self):
        self.Packets = []
        self.Flows={}
    def Setup_Flow(self,
                   Flow='TRAFFIC', #'FTP_COMMAND' #'FTP_DATA'
                   ):
        
        FlowObject = TCP_flow_control()
        FlowObject.Sync_Flow(dmac = self.dmac,
                               smac = self.smac,
                               src = self.src,
                               dst = self.dst,
                             srcv6 = self.srcv6,
                             dstv6 = self.dstv6,
                               dport = self.dport,
                               sport = self.sport,
                               InitClientSeq = self.InitClientSeq,
                               InitServerSeq = self.InitServerSeq)
        self.Flows[Flow] = FlowObject
 
        
    def SetVariables(self,
                       dmac = '11:22:33:44:55:66',
                       smac = '22:33:44:55:66:77',
                       TYPE= 'IPv4',
                       src = '1.1.1.1',
                       dst = '2.2.2.2',
                       sport = 1234,
                       dport = 80,
                       INTF = 'wlan0',
                       InitClientSeq=1,
                       InitServerSeq=1,
                       rlength = 1500,
                       Verbose = None,
                     ):
        self.dmac = dmac
        self.smac = smac
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.INTF = INTF
        self.InitClientSeq=InitClientSeq
        self.InitServerSeq=InitServerSeq
        self.rlength = rlength
        self.Verbose = Verbose

    def UDP_PORT_SCAN(self,
                      attempts = 2,
                      NetworkUnderAttack = None,
                      portRangeStart=80,
                      portRangeStop=81,
                      sportRangeStart=5555,
                      sportRangeStop=5556,
                      Types = [1,
                               2,
                               ],
                      ):
        self.UDP_Scan(attempts = attempts,
                      NetworkUnderAttack = NetworkUnderAttack,
                      portRangeStart = portRangeStart,
                      portRangeStop=portRangeStop,
                      sportRangeStart=sportRangeStart,
                      sportRangeStop=sportRangeStop,
                      Types = Types,
                      )
        
        
    
                      
    def TCP_PORT_SCAN(self,
                  syncattempts = 5,
                  NetworkUnderAttack = None,
                  portRangeStart=80,
                  portRangeStop=81,
                  sportRangeStart=5555,
                    sportRangeStop=5556,
                  Types = [1,
                           3,
                           #4,
                           ]):
        #print 'port range', portRangeStart,portRangeStop
        #print 'sport range', sportRangeStart, sportRangeStop
        self.SYNC_ATTACK(syncattempts = syncattempts,
                         NetworkUnderAttack = NetworkUnderAttack,
                         portRangeStart=portRangeStart,
                         portRangeStop=portRangeStop,
                         sportRangeStart=sportRangeStart,
                         sportRangeStop=sportRangeStop,
                         Types = Types)
        
                  
    def UDP_Scan(self,
                 attempts = 2,
                 NetworkUnderAttack = None,
                    portRangeStart=None,
                    portRangeStop=None,
                    sportRangeStart=None,
                    sportRangeStop=None,
                    Types = None,
                 ):
        TYPES = []
        if type(Types) == int:
            TYPES.append(TYPE)
        elif type(Types) == list or type(Types) == tuple:
            TYPES = Types
        else:
            TYPES = [1,2]
            
        dstips = []
        if NetworkUnderAttack != None:
        #    print 'SYNC ATTACK for Network', NetworkUnderAttack
            ip, Netmask = NetworkUnderAttack.split('/')
            dstips= GetIpsInNetwork(ip = ip,
                                    netmask = Netmask)
        else:
            dst = GenerateRandomIp()
            dstips.append(dst)
        for i in range(attempts):
            for dip in dstips:
                dmac = GenerateRandomMac()
                for port in range(portRangeStart,portRangeStop):
                    TYPE = random.choice(TYPES)
                    for sport in range(sportRangeStart,sportRangeStop):
                        Packets = []
                        if port == 53:
                            requestPacket= Ether(dst=dmac, src=self.smac, type=0x0800) / IP(src=self.src, dst=dip, proto='udp') /UDP(sport=sport, dport = port)/DNS(opcode="STATUS")
                            Packets.append(requestPacket)
                            if TYPE == 1: # deny
                                requestPacket= Ether(dst=self.smac, src=dmac, type=0x0800) / IP(src=dip, dst=self.src, proto='icmp') /ICMP(type='dest-unreach', code='port-unreachable')/IPerror(proto='udp', src=self.src, dst=dip)/UDPerror(sport=sport,dport=port)/DNS(opcode="STATUS")   
                                Packets.append(requestPacket)
                        elif port == 111:
                            LOAD = RamdomRawData(size=32)
                            requestPacket= Ether(dst=dmac, src=self.smac, type=0x0800) / IP(src=self.src, dst=dip, proto='udp') /UDP(sport=sport, dport = port)/Raw(load=LOAD)
                            Packets.append(requestPacket)
                            if TYPE == 1: # deny
                                requestPacket= Ether(dst=self.smac, src=dmac, type=0x0800) / IP(src=dip, dst=self.src, proto='icmp') /ICMP(type='dest-unreach', code='port-unreachable')/IPerror(proto='udp', src=self.src, dst=dip)/UDPerror(sport=sport,dport=port)/Raw(load=LOAD)
                                Packets.append(requestPacket)
                        elif port == 2049:
                            LOAD = RamdomRawData(size=40)
                            requestPacket= Ether(dst=dmac, src=self.smac, type=0x0800) / IP(src=self.src, dst=dip, proto='udp') /UDP(sport=sport, dport = port)/Raw(load=LOAD)    
                            Packets.append(requestPacket)
                            if TYPE == 1: # deny
                                requestPacket= Ether(dst=self.smac, src=dmac, type=0x0800) / IP(src=dip, dst=self.src, proto='icmp') /ICMP(type='dest-unreach', code='port-unreachable')/IPerror(proto='udp', src=self.src, dst=dip)/UDPerror(sport=sport,dport=port)/Raw(load=LOAD)
                                Packets.append(requestPacket)
                            
                        elif port == 500:
                            LOAD = RamdomRawData(size=192)
                            requestPacket= Ether(dst=dmac, src=self.smac, type=0x0800) / IP(src=self.src, dst=dip, proto='udp') /UDP(sport=sport, dport = port)/Raw(load=LOAD)
                            Packets.append(requestPacket)
                            if TYPE == 1: # deny
                                requestPacket= Ether(dst=self.smac, src=dmac, type=0x0800) / IP(src=dip, dst=self.src, proto='icmp') /ICMP(type='dest-unreach', code='port-unreachable')/IPerror(proto='udp', src=self.src, dst=dip)/UDPerror(sport=sport,dport=port)/Raw(load=LOAD)
                                Packets.append(requestPacket)
                            
                        elif port == 161:  #NOT SURE ABOUT THIS ONE....
                            LOAD = RamdomRawData(size=38)
                            requestPacket= Ether(dst=dmac, src=self.smac, type=0x0800) / IP(src=self.src, dst=dip, proto='udp') /UDP(sport=sport, dport = port)/SNMP()/ Raw(load=LOAD)
                            Packets.append(requestPacket)
                            if TYPE == 1: # deny
                                requestPacket= Ether(dst=self.smac, src=dmac, type=0x0800) / IP(src=dip, dst=self.src, proto='icmp') /ICMP(type='dest-unreach', code='port-unreachable')/SNMP()/IPerror(proto='udp', src=self.src, dst=dip)/UDPerror(sport=sport,dport=port)/Raw(load=LOAD)
                                Packets.append(requestPacket)
                            
                        else:
                            requestPacket= Ether(dst=dmac, src=self.smac, type=0x0800) / IP(src=self.src, dst=dip, proto='udp') / UDP(sport=sport, dport = port)
                            Packets.append(requestPacket)
                            if TYPE == 1: # deny
                                requestPacket= Ether(dst=self.smac, src=dmac, type=0x0800) / IP(src=dip, dst=self.src, proto='icmp') /ICMP(type='dest-unreach', code='port-unreachable')/IPerror(proto='udp', src=self.src, dst=dip)/UDPerror(sport=sport,dport=port)

                                Packets.append(requestPacket)
                            
                        sendp(Packets, iface = self.INTF)
                        
                   
        
    def SYNC_ATTACK(self,
                    syncattempts = 5,
                    NetworkUnderAttack = None,
                    portRangeStart=None,
                    portRangeStop=None,
                    sportRangeStart=None,
                    sportRangeStop=None,
                    Types = None):
        TYPES = []
        if type(Types) == int:
            TYPES.append(TYPE)
        elif type(Types) == list or type(Types) == tuple:
            TYPES = Types
        else:
            TYPES = [1,2,3,4]
            
        dstips = []
        if NetworkUnderAttack != None:
        #    print 'SYNC ATTACK for Network', NetworkUnderAttack
            IP, Netmask = NetworkUnderAttack.split('/')
            dstips= GetIpsInNetwork(ip = IP,
                                    netmask = Netmask)
        else:
            dst = GenerateRandomIp()
            dstips.append(dst)
        #print 'ips for sync try', dstips 
        for i in range(syncattempts):
            for dst in dstips:
                dmac = GenerateRandomMac()
                for port in range(portRangeStart,portRangeStop):
                    TYPE = random.choice(TYPES)
                    
                    for sport in range(sportRangeStart,sportRangeStop):
                        if TYPE == 1: #just send sync but no one answer
                            for i in range(5):
                                FlowObject = TCP_flow_control()
                                FlowObject.Sync_Flow(dmac = dmac,
                                                 smac = self.smac,
                                                 src = self.src,
                                                 dst = dst,
                                                 dport = port,
                                                 sport = sport,
                                                 InitClientSeq = 1,
                                                 InitServerSeq = 1,
                                                 Type = 'fail',
                                                     ipid = 1+i)
                                sendp(FlowObject.packets, iface = self.INTF)
                                FlowObject.packets = []
                        elif TYPE == 2:
                            for i in range(5):
                                FlowObject = TCP_flow_control()
                                FlowObject.Sync_Flow(dmac = dmac,
                                                 smac = self.smac,
                                                 src = self.src,
                                                 dst = dst,
                                                 dport = port,
                                                 sport = sport,
                                                 InitClientSeq = 1,
                                                 InitServerSeq = 1,
                                                 Type = 'dos',
                                                     ipid = 1+i)
                                sendp(FlowObject.packets, iface = self.INTF)
                                FlowObject.packets = []
                        elif TYPE == 3: #SYNC WITH RESET
                            FlowObject = TCP_flow_control()
                            FlowObject.Sync_Flow(dmac = dmac,
                                             smac = self.smac,
                                             src = self.src,
                                             dst = dst,
                                             dport = port,
                                             sport = sport,
                                             InitClientSeq = 1,
                                             InitServerSeq = 1,
                                             Type = 'deny')
                            #self.Packets += FlowObject.packets
                            #FlowObject.packets = []
                            sendp(FlowObject.packets, iface = self.INTF)
                            FlowObject.packets = []
                        elif TYPE == 4: #SYNC WITH RESET
                            FlowObject = TCP_flow_control()
                            FlowObject.Sync_Flow(dmac = dmac,
                                             smac = self.smac,
                                             src = self.src,
                                             dst = dst,
                                             dport = port,
                                             sport = sport,
                                             InitClientSeq = 1,
                                             InitServerSeq = 1,
                                             Type = None)
                            #self.Packets += FlowObject.packets
                            #FlowObject.packets = []
                            sendp(FlowObject.packets, iface = self.INTF)
                            FlowObject.packets = []
                           
                                
                                

            
        
