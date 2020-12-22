import cStringIO
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import gzip
import time
from Scapy_Control import *
from SSL_TLS_Support import *

'''
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto import Random
BS = 16
key = hashlib.sha1("Nathan the Great").digest()[:BS]
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]
class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.urlsafe_b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.urlsafe_b64decode(enc.encode('utf-8'))
        iv = enc[:BS]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[BS:]))

'''
class TCP_flow_control():
    def __init__(self):
        self.sip = None
        self.dip = None
        self.sipv6 = None
        self.dipv6 = None
        self.dmac = None
        self.smac = None
        self.Ether = None
        self.IP = None
        self.IPv6 = None
        self.TCP = None
        self.UDP = None
        self.Raw = None
        self.packets = []
        self.LastRawSize = 0
        self.Onsrc = True
        self.ORIGINALSRC = None
        self.ORIGINALSRCv6 = None
        self.LastDataSrc = None
        self.vlanTag= None
        self.TLS=False
        self.SSL = SSL_TSL_Supprt()
        self.version = None
        self.issuer = None
        self.subject = None
        self.vlanTagType = 0
        self.timeoffset = 0  #seconds
        #self.AES = AESCipher(key)
    def Setup_Vlan(self,
                   vlanTag):
        self.vlanTag= vlanTag
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
        if TYPE == 'IPv6':
            self.type = 'IPv6'
        #print 'ether set', self.Ether.display
    def SetupIpv6(self,
                version = None,
                tc = None,
                fl = None,
                plen = None,
                nh = 6,  #for TCP
                hlim = None,
                src = None,
                dst = None,
                ):
        self.IPv6 = IPv6()
        if version != None:
            self.IPv6.version = version
        if tc != None:
            self.IPv6.tc = tc
        if plen != None:
            self.IPv6.plen = plen
        if fl != None:
            self.IPv6.fl = fl
        if nh != None:
            self.IPv6.nh = nh
        if hlim != None:
            self.IPv6.hlim = hlim
        if src != None:
            self.IPv6.src = src
            self.ORIGINALSRCv6 = src
        if dst != None:
            self.IPv6.dst = dst
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
                ID= None):
        
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
        if ID != None:
            self.IP.id = ID
        #to do options --> not sure what is does now
        #print 'ip set', self.IP.display()
    def SetupTCP(self,
                 sport= None,
                 dport= None,
                 seq= None,
                 ack= None,
                 dataofs= None,
                 reserved= None,
                 flags= None,
                 window= None,
                 chksum= None,
                 urgptr= None,
                 options= {},
                 ):
        self.TCP = TCP()
        #print 'tcp orig', self.TCP.display()
        if sport != None:
            self.TCP.sport = int(sport)
        if dport != None:
            self.TCP.dport = int(dport)
        if seq != None:
            self.TCP.seq = int(seq)
        if ack != None:
            self.TCP.ack = int(ack)
        if dataofs != None:
            self.TCP.dataofs = dataofs
        if reserved != None:
            self.TCP.reserved = reserved
        if flags != None:
            self.TCP.flags = flags
        if window != None:
            self.TCP.window = window
        if chksum != None:
            self.TCP.chksum = chksum
        if urgptr != None:
            self.TCP.urgptr = urgptr
        if reserved != None:
            self.TCP.reserved = reserved
        #to do options --> not sure what is does now
        #print 'tcp set', self.TCP.display()

    def SetRawData(self,
                   load=None,
                   ):
        self.Raw = Raw()
        if load != None:
            self.Raw.load = load
        #print 'raw set', self.Raw.display()


    def Sync_Flow (self,
                   dmac = '11:22:33:44:55:66',
                   smac = '22:33:44:55:66:77',
                   TYPE= 'IPv4',
                   src = '1.1.1.1',
                   dst = '2.2.2.2',
                   srcv6 = None,
                   dstv6 = None,
                   dport = 7777,
                   sport = 6666,
                   InitClientSeq = 1,
                   InitServerSeq = 1,
                   ipid = None,
                   Type = None,
                   vlanTag = None,
                   version = "TLS_1_0",
                   issuer = None,
                   ssl_tls= False,
                   timeoffset=0):
        self.timeoffset = timeoffset
        if ssl_tls:
            subject = ssl_tls
        #print 'initializing flow'
        #print 'init with client seq', InitClientSeq
        #print 'init with server seq', InitServerSeq
        #setup flow
        self.SetupEther(dmac = dmac,
                        smac = smac,
                        TYPE= TYPE)


        if vlanTag != None:
            assert isinstance(int(vlanTag),int), 'vlan is not integer. is %s' %str(vlanTag)
            self.Setup_Vlan(vlanTag)
        if src != None or dst != None:
            self.SetupIp(src = src,
                         dst = dst,
                         ID = ipid,
                         flags = 'DF')
        if srcv6 != None or dstv6 != None:
            self.SetupIpv6(src = srcv6,
                           dst = dstv6,
                           )
        
        
        self.SetupTCP(sport = sport ,
                      dport = dport,
                      )
        
        if InitClientSeq == 1:
            CSEQ = RandomSafeSeqGenerator()
        else:
            CSEQ = InitClientSeq
        if InitServerSeq == 1:
            SSEQ = RandomSafeSeqGenerator()
        else:
            SSEQ = InitServerSeq
        #lets sync the source and destination addresses
        self.TCP.flags = 'S'
        self.TCP.ack = 0
        self.TCP.seq = CSEQ
        Ack=self.TCP.ack
        Seq=self.TCP.seq
        self.AttachPacket(Value = 14)

        if Type == None:
            #Server SYNC ACKNOWLEDGE
            self.SwapSrc_Dst()
            self.TCP.ack = Seq + 1
            self.TCP.seq = SSEQ
            self.TCP.flags = 'SA'
            self.AttachPacket(Value = 14)

            #Client will acknowledge Server
            self.SwapSrc_Dst()
            self.TCP.flags = 'A'
            self.TCP.ack += 1
            self.AttachPacket(Value = 14)
        elif Type.lower() == 'fail':
            pass #no more packets
        elif Type.lower() == 'deny':
            #Server SYNC ACKNOWLEDGE Reject
            self.SwapSrc_Dst()
            self.TCP.ack = Seq + 1
            self.TCP.seq = SSEQ
            self.TCP.flags = 'RA'
            self.AttachPacket(Value = 14)
        elif Type.lower() == 'dos':
            self.SwapSrc_Dst()
            self.TCP.ack = Seq + 1
            self.TCP.seq = SSEQ
            self.TCP.flags = 'SA'
           
        
        #lets do a TLS Handshake
        if ssl_tls:
            print 'setting up ssl handshake'
            #clientHello
            self.ConStruct_Packet_Without_Data(fromSrc=True,
                                               Flags = 'PA',
                                               AttachLayers=self.SSL.simple_clientHello(tlsrecord_version=version))
            self.ConStruct_Packet_Without_Data(fromSrc=False)  #server acknowledge

            #serverHello
            self.ConStruct_Packet_Without_Data(fromSrc=False,
                                               Flags = 'PA',
                                               AttachLayers=self.SSL.simple_serverHello(tlsrecord_version=version))
            self.ConStruct_Packet_Without_Data(fromSrc=True)  #client acknowledge

            if "ssl" in version.lower():
                pass  #certificate is in hello raw (static set to 400 bytes random data)
            else:
                #certificate
                self.ConStruct_Packet_Without_Data(fromSrc=False,
                                                   Flags = 'PA',
                                                   AttachLayers=self.SSL.simple_server_certificate(tlsrecord_version=version,
                                                                                                   subject=subject,
                                                                                                   issuer=issuer))
                self.ConStruct_Packet_Without_Data(fromSrc=True)  #client acknowledge

                #serverHelloDone
                self.ConStruct_Packet_Without_Data(fromSrc=False,
                                                   Flags = 'PA',
                                                   AttachLayers=self.SSL.simple_server_hello_done(tlsrecord_version=version))
                self.ConStruct_Packet_Without_Data(fromSrc=True)  #client acknowledge

            #clientKeyExchange
            self.ConStruct_Packet_Without_Data(fromSrc=True,
                                               Flags = 'PA',
                                               AttachLayers=self.SSL.simple_ClientKeyExchange(tlsrecord_version=version))
            self.ConStruct_Packet_Without_Data(fromSrc=False)  #server acknowledge

            if "ssl" in version.lower():
                #send random encrypted data
                self.ConStruct_Packet_Without_Data(fromSrc=False,
                                               Flags = 'PA',
                                               AttachLayers=self.SSL.encrypted_data())
                #send random encrypted data
                self.ConStruct_Packet_Without_Data(fromSrc=False,
                                               Flags = 'PA',
                                               AttachLayers=self.SSL.encrypted_data())
            else:
                #clientCipherSpec
                self.ConStruct_Packet_Without_Data(fromSrc=True,
                                                   Flags = 'PA',
                                                   AttachLayers=self.SSL.simple_Client_ChangeCipherSpec(tlsrecord_version=version))
                self.ConStruct_Packet_Without_Data(fromSrc=False)  #server acknowledge

                #clientFinished
                self.ConStruct_Packet_Without_Data(fromSrc=True,
                                                   Flags = 'PA',
                                                   AttachLayers=self.SSL.Finished(tlsrecord_version=version))
                self.ConStruct_Packet_Without_Data(fromSrc=False)  #server acknowledge

                #serverCipherSpec
                self.ConStruct_Packet_Without_Data(fromSrc=False,
                                                   Flags = 'PA',
                                                   AttachLayers=self.SSL.simple_Server_ChangeCipherSpec(tlsrecord_version=version))
                self.ConStruct_Packet_Without_Data(fromSrc=True)  #client acknowledge

                #serverFinished
                self.ConStruct_Packet_Without_Data(fromSrc=False,
                                                   Flags = 'PA',
                                                   AttachLayers=self.SSL.Finished(tlsrecord_version=version))
                self.ConStruct_Packet_Without_Data(fromSrc=True)  #client acknowledge



    def reset_Flow(self,
                   fromSrc=False,
                   ):
        if self.Onsrc!=fromSrc:
            self.SwapSrc_Dst()

        self.TCP.flags = 'R'
        if self.LastDataSrc == True:
            self.TCP.seq += self.LastRawSize
        else:
            self.TCP.ack += self.LastRawSize
        self.AttachPacket(Value = 14)

    def Fin_Flow(self):
        
        if self.Onsrc == False:
            self.SwapSrc_Dst()
        #client fin
        self.TCP.flags = 'FA'
        if self.LastDataSrc == True:
            self.TCP.seq += self.LastRawSize
        else:
            self.TCP.ack += self.LastRawSize
        self.AttachPacket(Value = 14)

        #Server fin 
        self.SwapSrc_Dst()
        self.TCP.flags = 'FA'
        self.TCP.ack += 1
        self.AttachPacket(Value = 14) 

        #Client acknowledge
        self.SwapSrc_Dst()
        self.TCP.flags = 'A'
        self.TCP.ack += 1
        self.AttachPacket(Value = 14)
        #print self.TCP.seq, self.TCP.ack
        return self.TCP.seq, self.TCP.ack
    def SwapSrc_Dst(self):
        sport = self.TCP.sport
        dport = self.TCP.dport
        if self.IP != None:
            sip = self.IP.src
            dip = self.IP.dst
            self.IP.dst = sip
            self.IP.src = dip
        if self.IPv6 != None:
            sip = self.IPv6.src
            dip = self.IPv6.dst
            self.IPv6.dst = sip
            self.IPv6.src = dip
        
        smac = self.Ether.src
        dmac = self.Ether.dst
        
        self.TCP.sport = dport
        self.TCP.dport = sport
        
        self.Ether.src = dmac
        self.Ether.dst = smac
        if self.Onsrc == True:
            self.Onsrc = False
        elif self.Onsrc == False:
            self.Onsrc = True
        SEQ = self.TCP.seq
        ACK = self.TCP.ack
        self.TCP.seq = ACK
        self.TCP.ack = SEQ
    def AttachPacket(self,
                     Value = None,
                     AttachLayers=None,  #whenever calling this function with this, attach layers may have raw, so dont use value 15
                     ):
        sendValue = 0
        if Value != None:
            sendValue = Value
        else:
            if self.Ether != None:
               sendValue += 8
            if self.IP != None or self.IPv6 != None:
                sendValue += 4
            if self.TCP != None:
                sendValue += 2
            if self.Raw != None:
                sendValue += 1
        self.LastRawSize = 0
        
        if sendValue == 8:
            packet = self.Ether
            self.packets.append(packet)
        elif sendValue == 12:
            if self.IP != None and self.IPv6 == None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IP
                else:
                    packet = self.Ether/self.IP
                packet[IP].len = len(packet[IP])
                del packet[IP].chksum
            elif self.IP != None and self.IPv6 != None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IP/self.IPv6
                else:
                    packet = self.Ether/self.IP/self.IPv6

                del packet[IP].chksum
                packet[IPv6].plen = len(packet[IPv6])-40
               
            elif self.IP == None and self.IPv6 != None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IPv6
                else:
                    packet = self.Ether/self.IPv6
                packet[IPv6].plen = len(packet[IPv6])-40

            else:
                raise Exception ('ip value set for parsing but no there is no ip set')
            try:      
                if packet[IP].src == self.ORIGINALSRC:
                    self.LastDataSrc = True
                else:
                    self.LastDataSrc = False
            except:
                if packet[IPv6].src == self.ORIGINALSRCv6:
                    self.LastDataSrc = True
                else:
                    self.LastDataSrc = False
            self.packets.append(packet)
        elif sendValue == 14:
            if self.IP != None and self.IPv6 == None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IP/self.TCP
                else:
                    packet = self.Ether/self.IP/self.TCP
                packet[IP].len = len(packet[IP])
                del packet[IP].chksum
            elif self.IP != None and self.IPv6 != None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IP/self.IPv6/self.TCP
                else:
                    packet = self.Ether/self.IP/self.IPv6/self.TCP
                del packet[IP].chksum
                packet[IPv6].plen = len(packet[IPv6])-40

            elif self.IP == None and self.IPv6 != None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IPv6/self.TCP
                else:
                    packet = self.Ether/self.IPv6/self.TCP
                packet[IPv6].plen = len(packet[IPv6])-40

            else:
                raise Exception ('ip value set for parsing but no there is no ip set')
            del packet[TCP].chksum
            try:      
                if packet[IP].src == self.ORIGINALSRC:
                    self.LastDataSrc = True
                else:
                    self.LastDataSrc = False
            except:
                if packet[IPv6].src == self.ORIGINALSRCv6:
                    self.LastDataSrc = True
                else:
                    self.LastDataSrc = False
            
        elif sendValue == 15:
            if self.IP != None and self.IPv6 == None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IP/self.TCP/self.Raw
                else:
                    packet = self.Ether/self.IP/self.TCP/self.Raw
                packet[IP].len = len(packet[IP])
                del packet[IP].chksum
            elif self.IP != None and self.IPv6 != None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IP/self.IPv6/self.TCP/self.Raw
                else:
                    packet = self.Ether/self.IP/self.IPv6/self.TCP/self.Raw
                del packet[IP].chksum
                packet[IPv6].plen = len(packet[IPv6])-40
               
            elif self.IP == None and self.IPv6 != None:
                if self.vlanTag != None:
                    packet = self.Ether/Dot1Q(vlan= self.vlanTag, type=self.vlanTagType)/self.IPv6/self.TCP/self.Raw
                else:
                    packet = self.Ether/self.IPv6/self.TCP/self.Raw
                packet[IPv6].plen = len(packet[IPv6])-40

            else:
                raise Exception ('ip value set for parsing but no there is no ip set')
            del packet[TCP].chksum
            try:      
                if packet[IP].src == self.ORIGINALSRC:
                    self.LastDataSrc = True
                else:
                    self.LastDataSrc = False
            except:
                if packet[IPv6].src == self.ORIGINALSRCv6:
                    self.LastDataSrc = True
                else:
                    self.LastDataSrc = False
            self.LastRawSize = len(packet[Raw])
            
        else:
            raise Exception('error %i' %sendValue)

        if AttachLayers:  #works with application/ssl layers consisting of data to increase last Raw Size  !!!NOT LAYER 2-4!!!
            #dont attach with Raw data
            assert sendValue!=15, 'dont attach to raw'
            packet=packet/AttachLayers
            #print len(AttachLayers)
            #print 'show'
            #AttachLayers.show2()
            #p.show2()
            if packet.haslayer(IP):
                packet[IP].len = len(packet[IP])

                del packet[IP].chksum
            if packet.haslayer(TCP):
                del packet[TCP].chksum

            self.LastRawSize = len(AttachLayers)
        if packet.haslayer(IP):
            packet[IP].len = len(packet[IP])

            del packet[IP].chksum
        if packet.haslayer(TCP):
            del packet[TCP].chksum
        #packet.show2()
        packet.time = int(time.time()) - int(self.timeoffset)

        self.packets.append(packet)
    def ConStruct_Packet_Without_Data(self,
                        fromSrc = True,
                        Flags = 'A',
                        AttachLayers=None):
        if self.Onsrc != fromSrc:
            self.SwapSrc_Dst()
        self.TCP.flags = Flags
        if self.LastDataSrc == fromSrc:
            self.TCP.seq += self.LastRawSize
        else:
            self.TCP.ack += self.LastRawSize
        self.AttachPacket(Value=14,
                          AttachLayers=AttachLayers)

    def ConStruct_Packet_With_Data(self,
                                   fromSrc = True,
                                   data= None,
                                   Flags = 'PA'):
        assert data != None, 'must set raw data'
        assert ( type(data) == str ) or ( type(data) == unicode ), 'data must be string'
        if self.Onsrc != fromSrc:
            self.SwapSrc_Dst()
        self.TCP.flags = Flags
        if self.LastDataSrc == fromSrc:
            self.TCP.seq += self.LastRawSize
        else:
            self.TCP.ack += self.LastRawSize

        if self.TLS:  # lets load
            data = RamdomRawData(len(data))#self.AES.encrypt(data)
            AttachLayers=SSL(records=[TLSRecord(content_type="application_data")/TLSCiphertext(data=data)])
            self.AttachPacket(AttachLayers=AttachLayers)
        else:
            self.SetRawData(load=data)
            self.AttachPacket()
    def Download_Segment(self,
                         FILE = None, #
                         StartRead = 0, #place to read file
                         BytesToRead = 0, #place to finish
                         rlength = 1000,
                         ):
        
        assert os.path.exists(FILE) == True, '%s does not exist' %FILE
        assert BytesToRead != 0, 'must specify bytes to read'
        
        read = open(FILE, 'rb').read()
        
        FILESIZE = len(read)
        assert StartRead < FILESIZE, 'cant start read at bytes greater then file'
        if StartRead + BytesToRead > FILESIZE:
            BytesToRead = FILESIZE - StartRead
        #print 'downloading segement', StartRead, 'to', StartRead +BytesToRead
        if self.IP != None and self.IPv6 != None:
            rlength = rlength - len(self.Ether/self.IP/self.IPv6/self.TCP)
        if self.IP == None and self.IPv6 != None:
            rlength = rlength - len(self.Ether/self.IPv6/self.TCP)
        if self.IP != None and self.IPv6 == None:
            rlength = rlength - len(self.Ether/self.IP/self.TCP)
        BytesLeft = BytesToRead
        x = StartRead
        while BytesLeft > 0:
            DATA = read[x:x+rlength]
            x += rlength
            BytesLeft -= rlength
            if BytesLeft < 1:
                #send the PA on the last transfer packet
                self.ConStruct_Packet_With_Data(fromSrc=False,
                                                data=DATA,
                                                Flags = 'PA')
            else:
                self.ConStruct_Packet_With_Data(fromSrc=False,
                                                   data=DATA,
                                                   Flags = 'A')

            self.ConStruct_Packet_Without_Data(fromSrc = True)



    def Download_File(self,
                      FILE = None,
                      GZIP = False,
                      CHUNKED = False,
                      rlength = 1000,
                      randomized = False,
                      wait = 0,
                      INTF = None,
                      DATAONLY = 0):

        if DATAONLY == 0:
            assert os.path.exists(FILE), '%s does not exist, can not generate full pcap' %FILE
            print 'datafile', os.path.abspath(FILE)
            if randomized != False:
                F = File_Modifyer(FILE,
                                  OutputFile = 'scapyrandomfile',
                                  AddBytes = randomized)

                if GZIP == True:
                    f = gzip.open('f.gz', 'wb')
                    f.write(open('scapyrandomfile', 'rb').read())
                    f.close()
                    FILESIZE = len(open('f.gz', 'rb').read())
                    f = open('f.gz','rb')
                else:
                    oldFILESIZE = len(open(FILE, 'rb').read())
                    FILESIZE = len(open('scapyrandomfile', 'rb').read())
                    #print 'oldFile:', oldFILESIZE
                    #print 'newFile:', FILESIZE
                    f=open('scapyrandomfile','rb')
            else:
                if GZIP == True:
                    f = gzip.open('f.gz', 'wb')
                    f.write(open(FILE, 'rb').read())
                    f.close()
                    FILESIZE = len(open('f.gz', 'rb').read())
                    f = open('f.gz','rb')
                else:
                    FILESIZE = len(open(FILE, 'rb').read())
                    f = open(FILE, 'rb')
            BytesLeft =  FILESIZE

        elif DATAONLY > 0:
            f = cStringIO.StringIO(RamdomRawData(DATAONLY))
            f.seek(0)
            BytesLeft =  DATAONLY


        if self.IP != None and self.IPv6 != None:
            rlength = rlength - len(self.Ether/self.IP/self.IPv6/self.TCP)
        if self.IP == None and self.IPv6 != None:
            rlength = rlength - len(self.Ether/self.IPv6/self.TCP)
        if self.IP != None and self.IPv6 == None:
            rlength = rlength - len(self.Ether/self.IP/self.TCP)

        if CHUNKED != False:
            ### lets try something here and create larger chunk sizes that can expand over several packets and also in the middle of packets
            print 'number of CHUNKS', CHUNKED
            # for this te
            CHUNKED = int(CHUNKED)
            Output = cStringIO.StringIO()

            CHUNKED = FILESIZE/CHUNKED
            if CHUNKED < 3:
                print 'chunk size calculated is less.  chuck size will be 3 bytes and number of chunks will not be accurate'
                CHUNKED = 3
            print 'CHUNK SIZE',  CHUNKED
            BREAD= 0
            BLEFT=BytesLeft
            Total = 0
            while BLEFT > 0:
                if BLEFT==BytesLeft:
                    DATA = '%X\r\n%s\r\n' % (CHUNKED-2, f.read(CHUNKED-2))
                    BREAD += (CHUNKED-2)
                    BLEFT -= (CHUNKED-2)
                    Output.write(DATA)
                    Total += len(DATA)

                if BLEFT > CHUNKED and BLEFT < BytesLeft :
                    DATA = '%X\r\n%s\r\n' % (CHUNKED, f.read(CHUNKED))
                    BREAD += CHUNKED
                    BLEFT -= CHUNKED
                    Output.write(DATA)
                    Total += len(DATA)
                elif BLEFT < CHUNKED:
                    DATA = '%X\r\n%s\r\n0\r\n\r\n' % (BLEFT, f.read(BLEFT))
                    BREAD += BLEFT
                    BLEFT -= BLEFT
                    Output.write(DATA)
                    Total += len(DATA)
                    break
            f = Output
            f.seek(0)
            BytesLeft = Total
            #lest break up file into chunks


            #this is how it used to be
            #rlength = CHUNKED  no longer chunking every packet but



        BytesRead = 0
        while BytesLeft > 0:
            time.sleep(wait)
            #old way of doing chunked was per packet
            #if CHUNKED != False:
            #    if BytesLeft < rlength:
                    #print 'reading bytes', BytesLeft
            #        BytesRead +=BytesLeft
            #        DATA = '%X\r\n%s\r\n'%(BytesLeft, f.read(rlength))
            #    else:
            #        #print 'reading bytes', rlength
            #        BytesRead += rlength
            #        DATA = '%X\r\n%s\r\n'%(rlength, f.read(rlength))

            #else:
            DATA = f.read(rlength) #was in else statement above
            BytesRead += rlength #was in else statement above
            BytesLeft -= rlength

            if BytesLeft < 1:
                #send the PA on the last transfer packet

                ### old way of doing chuncked
                #if CHUNKED != False:
                #    self.ConStruct_Packet_With_Data(fromSrc=False,
                #                               data=DATA,
                #                               Flags = 'A')
                #    self.ConStruct_Packet_Without_Data(fromSrc = True)
                #
                #    self.ConStruct_Packet_With_Data(fromSrc=False,
                #                               data='0\r\n\r\n',
                #                               Flags = 'PA')
                    #self.ConStruct_Packet_Without_Data(fromSrc = True)
                #else:
                self.ConStruct_Packet_With_Data(fromSrc=False,
                                               data=DATA,
                                               Flags = 'PA')
                    #self.ConStruct_Packet_Without_Data(fromSrc = True)
                f.close()
                if GZIP == True:
                    os.remove('f.gz')
            else:
                self.ConStruct_Packet_With_Data(fromSrc=False,
                                                   data=DATA,
                                                   Flags = 'A')


            #if CHUNKED != False:
            #    self.ConStruct_Packet_With_Data(fromSrc=False,
            #                                    data='\r\n0\r\n\r\n',
            #                                    Flags='PA')
            self.ConStruct_Packet_Without_Data(fromSrc = True)
            if wait > 0:
                assert INTF != None, 'must specify intf if wait is greater than 0'
                sendp(self.packets, iface = INTF)
                self.packets = []
        #print 'BytesRead', BytesRead

    def Upload_File(self,
                    FILE = None,
                    rlength = 1000,
                    randomized = False,
                    wait = 0,
                    INTF = None,
                    DATAONLY = 0):
        if DATAONLY == 0:
            assert os.path.exists(FILE), '%s does not exist, can not generate full pcap' %FILE

        #lets recalculate rlenghth (1500 which is average mtu minus non raw data)
        if self.IP != None and self.IPv6 != None:
            rlength = rlength - len(self.Ether/self.IP/self.IPv6/self.TCP)
        if self.IP == None and self.IPv6 != None:
            rlength = rlength - len(self.Ether/self.IPv6/self.TCP)
        if self.IP != None and self.IPv6 == None:
            rlength = rlength - len(self.Ether/self.IP/self.TCP)

        if DATAONLY > 0:
            f = cStringIO.StringIO(RamdomRawData(DATAONLY))
            f.seek(0)
        else:
            if randomized != False:
                F = File_Modifyer(FILE,
                                  OutputFile = 'scapyrandomfile',
                                  AddBytes = randomized)
                FILESIZE = len(open('scapyrandomfile', 'rb').read())
                f=open('scapyrandomfile','rb')
            else:
                f = open(FILE, 'rb')
        EOF = 0
        while EOF == 0:
            time.sleep(wait)
            DATA = f.read(rlength)
            if len(DATA) < rlength:
                #close out file
                f.close()
                #send PA Flags on the last data tranfer packet
                self.ConStruct_Packet_With_Data(fromSrc=True,
                                           data=DATA,
                                           Flags = 'PA')
                #Server acknowledge only last transfer packet
                self.ConStruct_Packet_Without_Data(fromSrc = False)
                EOF = 1
            else:
                self.ConStruct_Packet_With_Data(fromSrc=True,
                                           data=DATA,
                                           Flags = 'A')
            if wait > 0:
                assert INTF != None, 'must specify intf if wait is greater than 0'
                sendp(self.packets, iface = INTF)
                self.packets = []

if __name__=='__main__':
    pcap = "/home/nathanhoisington/test.pcap"
    self = TCP_flow_control()
    self.Sync_Flow (dmac = '11:22:33:44:55:66',
                   smac = '22:33:44:55:66:77',
                   TYPE= 'IPv4',
                   src = '1.1.3.1',
                   dst = '2.2.4.2',
                   srcv6 = None,
                   dstv6 = None,
                   dport = 4444,
                   sport = 6666,
                   InitClientSeq = 1,
                   InitServerSeq = 1,
                   ipid = None,
                   Type = None,
                   vlanTag = None,
                   ssl_tls=True,
                   )
    #wrpcap(pcap,self.packets)
