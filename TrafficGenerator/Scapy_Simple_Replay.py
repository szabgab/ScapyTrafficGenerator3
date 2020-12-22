#! /usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os
import random
import sys, getopt
from time import sleep, time, gmtime
from subprocess import Popen, PIPE
from xml.dom.minidom import parse
import threading
from time import sleep, asctime
import re


                        
class Scapy_Simple_Replay():
    def __init__(self,
                 PCAPPATH):
        self.pcapfile = rdpcap(PCAPPATH)
        self.Packets = []
        self.INT = None
        
    def SetINTF (self,
                 INTF):
        self.INT = INTF

    #works for tcp traffic only
    def Alter_Ether_IP(self,
                       src=None,
                       dst=None,
                       src_set=None,
                       dst_set=None,
                       smac_set=None,
                       dmac_set=None,
                       ):
        assert src != None, 'must define src to alter'
        assert dst != None, 'must define dst to alter'
        print 'planing to set all src %s with src %s' %(src, src_set)
        print 'planning to set all dest %s with dst %s' %(dst, dst_set)
        for packet in self.pcapfile:
            if packet.haslayer(IP):
                if packet[IP].src == src:
                    if src_set != None:
                        packet[IP].src = src_set
                    if smac_set != None:
                        packet[Ether].dst = smac_set
                if packet[IP].dst == src:
                    if src_set != None:
                        packet[IP].dst = src_set
                    if smac_set != None:
                        packet[Ether].dst = smac_set
                if packet[IP].src == dst:
                    if dst_set != None:
                        packet[IP].src = dst_set
                    if dmac_set != None:
                        packet[Ether].src = dmac_set
                if packet[IP].dst == dst:
                    if dst_set != None:
                        packet[IP].dst = dst_set
                    if dmac_set != None:
                        packet[Ether].dst = dmac_set      
                        
                #recalculate IP len and checksum
                packet[IP].len = len(packet[IP])
                #print packet[IP].len
                del packet[IP].chksum
                if packet.haslayer(TCP):
                    del packet[TCP].chksum
            
            else:
                #lets not append unrelevent flow
                pass
                #self.Packets.append(packet)   
            self.Packets.append(packet)
                       
    def Alter_TCP_IP_ETHER(self,
                      src=None,
                      dst=None,
                      sport=None,
                      dport=None,
                      src_set=None,
                      dst_set=None,
                      sport_set=None,
                      dport_set=None,
                      smac_set=None,
                      dmac_set=None,
                      ):
        assert src != None, 'must define src to alter'
        assert dst != None, 'must define dst to alter'
        assert sport != None, 'must define src port'
        assert dport != None, 'must define dst port'
      
##        print 'set %s to %s' %(src, src_set)
##        print 'set %s to %s' %(dst, dst_set)
##        print 'set %s to %s' %(sport,sport_set)
##        print 'set %s to %s' %(dport,dport_set)
##        print 'set smac to', smac_set
##        print 'set dmac to', dmac_set
        
        
        for packet in  self.pcapfile:
            if packet.haslayer(TCP):
                 #alter sport for the specific set
##                print 'match', packet[IP].src, src, type(packet[IP].src),type(src)
##                print 'match', packet[TCP].sport, sport, type(packet[TCP].sport), type(sport)

                #alter sport/src for the specific set
                if packet[IP].src == src and packet[TCP].sport == sport:
                    if src_set != None:
                        packet[IP].src = src_set
                    if smac_set != None:
                        packet[Ether].src = smac_set
                    if sport_set != None:
                        packet[TCP].sport = sport_set
                if packet[IP].dst == src and packet[TCP].dport == sport:
                    if src_set != None:
                        packet[IP].dst = src_set
                    if smac_set != None:
                        packet[Ether].dst = smac_set
                    if sport_set != None:
                        packet[TCP].dport = sport_set
                        
                 #alter dport/dst for the specific set
                if packet[IP].src == dst and packet[TCP].sport == dport:
                    if dport_set != None:
                        packet[TCP].sport = dport_set
                    if dst_set != None:
                        packet[IP].src = dst_set
                    if dmac_set != None:
                        packet[Ether].src = dmac_set
                if packet[IP].dst == dst and packet[TCP].dport == dport:
                    if dport_set != None:
                        packet[TCP].dport = dport_set
                    if dst_set != None:
                        packet[IP].dst = dst_set
                    if dmac_set != None:
                        packet[Ether].dst = dmac_set
                        
                #recalculate IP len and checksum
                packet[IP].len = len(packet[IP])
                #print packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                
            else:
                #lets not append unrelevent flow
                pass
                #self.Packets.append(packet
            self.Packets.append(packet)
    def SendPcap(self,
                 outputfile = None,
                 Verbose = None):
        #print 'sending pcap'
        try:
            if Verbose == None: #dont set verbose
                sendp(self.Packets,iface=self.INT)
            else:
                assert type(Verbose) == int, 'Verbose must be defined as integer'
                sendp(self.Packets,iface=self.INT,verbose=Verbose)
        except Exception as error:
             print 'unable to send pcap with error:', error
             for i in range(len(self.Packets)):
                 print 'packet %i, len %i' %(i, len(self.Packets[i]))
            
            
        #write to pcap file
        if outputfile != None and outputfile != 'None':
            #print 'now writing pcap'
            try:
                 wrpcap(outputfile,self.Packets)
            except Exception as error:
                print 'unable to write pcap with error:', error
        
   

  
def main(argv):
    src=None
    dst=None
    sport=None
    dport=None
    src_set=None
    dst_set=None
    sport_set=None
    dport_set=None
    smac_set=None
    dmac_set=None
    outfile = None
    INT = None
    PCAPPATH = None
    Verbose = None
    try:
        opts, args = getopt.getopt(argv, 'i:o:I:s:d:S:D:m:M:x',['input=',
                                                          'output=',
                                                          'interface=',
                                                          'src=',
                                                          'dst=',
                                                          'src_set=',
                                                          'dst_set=',
                                                              'smac=',
                                                              'dmac=',
                                                                'verbose'
                                                              ]
                                   )
        
    except getopt.GetoptError:
        print 'failed to run error'
    for opt, arg in opts:
        if opt == '-i':
            PCAPPATH = arg.strip('\n')
        if opt == '-o':
            outfile = arg.strip('\n')
        if opt == '-I':
            INT = arg.strip('\n')
        if opt == '-s':
            SOURCE = arg.strip('\n').split(':')
            if len(SOURCE) == 1:
                src = SOURCE[0]
            elif len(SOURCE) == 2:
                src, sport = SOURCE
                sport = int(sport)
            else:
                raise Exception('too many arguments in %s' %str(SOURCE))
        if opt == '-d':
            DEST = arg.strip('\n').split(':')
            if len(DEST) == 1:
                dst = DEST[0]
            elif len(DEST) == 2:
                dst, dport = DEST
                dport = int(dport)
            else:
                raise Exception('too many arguments in %s' %str(SOURCE))
        if opt == '-S':
            SOURCE = arg.strip('\n').split(':')
            if len(SOURCE) == 1:
                src_set = SOURCE[0]
            elif len(SOURCE) == 2:
                src_set, sport_set = SOURCE
                sport_set = int(sport_set)
            else:
                raise Exception('too many arguments in %s' %str(SOURCE))
        if opt == '-D':
            DEST = arg.strip('\n').split(':')
            if len(DEST) == 1:
                dst_set = DEST[0]
            elif len(DEST) == 2:
                dst_set, dport_set = DEST
                dport_set = int(dport_set)
            else:
                raise Exception('too many arguments in %s' %str(SOURCE))
        if opt == '-m':
            smac_set = str(arg.strip('\n'))
        if opt == '-M':
            dmac_set = str(arg.strip('\n'))
        if opt == '-x':
            Verbose = 0
                
    assert INT != None, 'must define interface with -I'
    assert PCAPPATH != None, 'must define pcap path with -i'
    assert os.path.exists(PCAPPATH)==True, '%s does not exist' %os.path.abspath(PCAPPATH)
    
    self = Scapy_Simple_Replay(PCAPPATH)
    self.INT = INT
    if sport == None and dport == None:
        print 'altering ip'
        self.Alter_Ether_IP(src=src,
                       dst=dst,
                       src_set=src_set,
                       dst_set=dst_set,
                       smac_set=smac_set,
                       dmac_set=dmac_set,
                            )

    else:
        print 'altering tcp'
        self.Alter_TCP_IP_ETHER(src=src,
                           dst=dst,
                           sport=sport,
                           dport=dport,
                           src_set=src_set,
                           dst_set=dst_set,
                           sport_set=sport_set,
                           dport_set=dport_set,
                           smac_set=smac_set,
                          dmac_set=dmac_set)
    self.SendPcap(outputfile = outfile,
                  Verbose=Verbose)



    
    

if __name__ == '__main__':
    #p = Insert()
    main(sys.argv[1:])

'''
EXAMPLE USE
python Scapy_Simple_Replay.py -i imap.pcap -s 127.0.0.1:55211 -d 127.0.0.1:143 -S 1.1.1.1 -D 2.2.2.2 -m 11:11:11:11:11:11 -M 22:22:22:22:22:22 -o imap2.pcap
'''
##test mnt
#umount /mnt/tsn
#mount -t tmpfs -o size=4g none /mnt/tsn
#mount -t tmpfs -o size=4g tmpfs /mnt/tsn
