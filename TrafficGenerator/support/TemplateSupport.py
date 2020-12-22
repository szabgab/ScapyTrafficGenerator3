### THIS SUPPORT READS FROM PCAP FILE AND ALTERS ACCORDINGLY

import os

from TCP_flow_control import *
from Scapy_Control import RandomSafeSeqGenerator


###TEMPLATE HAS ONE FLOW

###TEMPLATE FOR MAPI
MapiTemplate = '%s/Pcaps/mapi.pcap' %os.getcwd()
MapiSrc = '192.168.0.173'
MapiDst = '192.168.0.2'
MapiName = 'ALeonard@192.168.0.2'
MapiUser = 'ALeonard'
#dport=23



###TEMPLATE FOR TELNET
TelnetTemplate = '%s/Pcaps/telnetTemplate.pcap' %os.getcwd()
TelnetSrc = '192.168.0.2'
TelnetDst = '192.168.0.1'
TelnetName = 'fake'
#dport=23
TelnetPassword = 'user'
TelnetType= 'xterm-color'

##TEMPLATE FOR SMB
SMBTemplate = '%s/Pcaps/smb.pcap' %os.getcwd()
SMBSrc = '67.84.15.125'
SMBDst = '128.206.3.192'
#dport= 139
SMBName = 'administrator'
SMBServer= 'ELISHEVA'

##Template for Radius
RadiusTemplate = '%s/Pcaps/radius.pcap' %os.getcwd()
RadiusSrc= '192.168.4.254'
RadiusDst= '10.0.2.102'
#dport= 1812
#sport= 1645
RadiusName = 'radiususer'


##Template for Diameter
DiameterTemplate = '%s/Pcaps/diameter.pcap' %os.getcwd()
DiameterSrc= '1.1.1.1'
DiameterDst= '2.2.2.2'
#dport= 3868
DiameterUser = 'user@domain.com'

##Template for tds
TDSTemplate = '%s/Pcaps/tds.pcap' %os.getcwd()
TDSSrc= '192.168.0.218'
TDSDst= '192.168.0.4'
TDSServer = 'zh'
TDSName = 'sa'
TDSHost= 'sqlserver'

##TEMPLATE FOR SSH
SSHTemplate = '%s/Pcaps/ssh.pcap' %os.getcwd()
SSHSrc = '10.22.25.82'
SMBDst = '10.21.11.131'


##TEMPLATE FOR krb5
KRBTemplate = '%s/Pcaps/krb-816.pcap' %os.getcwd()
KRBSrc = '10.1.12.2'
KRBDst = '10.5.3.1'

##TEMPLATE FOR RLOGIN
RLOGINTemplate = '%s/Pcaps/rlogin.pcap' %os.getcwd()
RLOGINSrc = '192.168.1.19'
RLOGINDst = '192.168.1.34'
RLOGIN_client_host = 'lol'
RLOGIN_client_login = 'root'

##TEMPLATE FOR pop3
pop3Template = '%s/Pcaps/pop3.pcap' %os.getcwd()
pop3Src = '192.168.9.3'
pop3Dst = '192.168.7.140'
pop3sp = 2058
pop3dp = 110
pop3smac = "00:A0:83:37:1D:7C"
pop3dmac = "00:E0:2B:83:EA:00"
pop3_client_login = 'test'

##TEMPLATE FOR imap
imapTemplate = '%s/Pcaps/imap.pcap' %os.getcwd()
imapSrc = '1.1.1.1'
imapDst = '2.2.2.2'
imap_client_login = 'fred'

##TEMPLATE FOR RSH
rshTemplate = '%s/Pcaps/rsh.pcap' %os.getcwd()
rshSrc = '1.1.3.14'
rshDst = '27.27.27.75'
rsh_client_name = 'clientName'
rsh_server_name = 'serverName'


##TEMPLATE FOR OTHER PCAP.  only support -s -S -d -D -m -M
### full path to template specified
class TemplateSupport():
    def __init__(self):
        self.Packets = []

    def SetVariables(self,
                       dmac = '11:22:33:44:55:66',
                       smac = '22:33:44:55:66:77',
                       TYPE= 'IPv4',
                       src = '1.1.1.1',
                       dst = '2.2.2.2',
                       sport = 1234,
                       dport = 23,
                       username = 'username',
                       password = 'password',
                       servername = 'servername',
                       hostname = 'shostname'):
        self.hostname=hostname
        self.servername = servername
        self.username=username
        self.password=password
        self.dmac = dmac
        self.smac = smac
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.InitClientSeq = RandomSafeSeqGenerator()
        self.InitServerSeq = RandomSafeSeqGenerator()

    def AlterPackets(self,
                     ReplaceList = [],  #['user', 'password'], ['fake', 'name']
                     originalSource = TelnetSrc,
                     pcap = TelnetTemplate):
        assert originalSource, 'must define an original source'
        self.pcapfile = rdpcap(pcap)


        print 'forming deltas'
        #Client side edit
        if self.pcapfile[0].haslayer(TCP):  #assume TCP connection and gather seq/awk data
            if int(self.InitClientSeq) < int(self.pcapfile[0][TCP].seq):
                deltaSeq = int(self.pcapfile[0][TCP].seq) - self.InitClientSeq
            elif self.InitClientSeq > int(self.pcapfile[0][TCP].seq):
                deltaSeq =  self.InitClientSeq - int(self.pcapfile[0][TCP].seq)

            #Server side edit
            if self.InitServerSeq < int(self.pcapfile[1][TCP].seq):
                deltaAck = int(self.pcapfile[1][TCP].seq) - self.InitServerSeq
            elif self.InitServerSeq > int(self.pcapfile[1][TCP].seq):
                deltaAck = self.InitServerSeq - int(self.pcapfile[1][TCP].seq)   #Client side edit

            print 'deltaSeq', deltaSeq
            print 'deltaAck', deltaAck
            print 'altering packets'
        else:  #assume udp
            deltaAck = 0
            deltaSeq = 0

        #print 'replace list', ReplaceList
        for packet in  range(len(self.pcapfile)):
            if self.pcapfile[packet].haslayer(Padding):
                #print 'packet number %i has padding. lets remove it' %packet
                self.pcapfile[packet][Padding] = None
            if packet == 0 and self.pcapfile[packet].haslayer(TCP):
                self.pcapfile[packet][TCP].sport = self.sport
                self.pcapfile[packet][IP].src = self.src
                self.pcapfile[packet][Ether].src = self.smac
                self.pcapfile[packet][TCP].dport = self.dport
                self.pcapfile[packet][IP].dst = self.dst
                self.pcapfile[packet][Ether].dst = self.dmac
                self.pcapfile[packet][TCP].seq = self.pcapfile[packet][TCP].seq + deltaSeq
                self.pcapfile[packet][TCP].ack = 0
                del self.pcapfile[packet][IP].chksum
                del self.pcapfile[packet][TCP].chksum
                self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
            else:
                if self.pcapfile[packet].haslayer(TCP):
                    #print 'TCP'
                    if self.pcapfile[packet][IP].src == originalSource:
                        self.pcapfile[packet][TCP].sport = self.sport
                        self.pcapfile[packet][IP].src = self.src
                        self.pcapfile[packet][Ether].src = self.smac
                        self.pcapfile[packet][TCP].dport = self.dport
                        self.pcapfile[packet][IP].dst = self.dst
                        self.pcapfile[packet][Ether].dst = self.dmac
                        self.pcapfile[packet][TCP].seq = self.pcapfile[packet][TCP].seq + deltaSeq
                        self.pcapfile[packet][TCP].ack = self.pcapfile[packet][TCP].ack + deltaAck
                        for Replace in ReplaceList:
                            ReplaceString,ReplaceWith = Replace
                            #print 'trying to replace', ReplaceString, 'with ',  ReplaceWith
                            if self.pcapfile[packet].haslayer(Raw):
                                load = self.Replace_Raw_Data(self.pcapfile[packet][Raw].load,
                                                             ReplaceString,
                                                             ReplaceWith,
                                                             )

                                if load != None:
                                    #print 'old raw', len(self.pcapfile[packet][Raw].load)
                                    #print 'new raw', len(load)

                                    deltaSeq += (len(load) - len(self.pcapfile[packet][Raw].load))
                                    #print 'new deltaSeq', deltaSeq
                                    #print 'deltaAck', deltaAck
                                    self.pcapfile[packet][Raw].load = load

                        self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                        del self.pcapfile[packet][IP].chksum
                        del self.pcapfile[packet][TCP].chksum
                    else:
                        self.pcapfile[packet][TCP].sport = self.dport
                        self.pcapfile[packet][IP].src = self.dst
                        self.pcapfile[packet][Ether].src = self.dmac
                        self.pcapfile[packet][TCP].dport = self.sport
                        self.pcapfile[packet][IP].dst = self.src
                        self.pcapfile[packet][Ether].dst = self.smac
                        self.pcapfile[packet][TCP].seq = self.pcapfile[packet][TCP].seq + deltaAck
                        self.pcapfile[packet][TCP].ack = self.pcapfile[packet][TCP].ack + deltaSeq
                        for Replace in ReplaceList:
                            ReplaceString,ReplaceWith = Replace
                            #print 'trying to replace', ReplaceString, 'with ',  ReplaceWith
                            if self.pcapfile[packet].haslayer(Raw):
                                load = self.Replace_Raw_Data(self.pcapfile[packet][Raw].load,
                                                             ReplaceString,
                                                             ReplaceWith,
                                                             )

                                if load != None:
                                    deltaAck += (len(load) - len(self.pcapfile[packet][Raw].load))
                                    #print 'setting ack +', deltaAck
                                    #print 'deltaSeq', deltaSeq
                                    #print 'new deltaAck', deltaAck
                                    self.pcapfile[packet][Raw].load = load


                        self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                        del self.pcapfile[packet][IP].chksum
                        del self.pcapfile[packet][TCP].chksum
                elif self.pcapfile[packet].haslayer(UDP):
                    #print 'UDP'
                    if self.pcapfile[packet][IP].src == originalSource:
                        self.pcapfile[packet][IP].src = self.src
                        self.pcapfile[packet][Ether].src = self.smac
                        self.pcapfile[packet][UDP].dport = self.dport
                        self.pcapfile[packet][IP].dst = self.dst
                        self.pcapfile[packet][Ether].dst = self.dmac
                        for Replace in ReplaceList:
                            ReplaceString,ReplaceWith = Replace
                            #print 'trying to replace', ReplaceString, 'with ',  ReplaceWith
                            if self.pcapfile[packet].haslayer(Raw):
                                load = self.Replace_Raw_Data(self.pcapfile[packet][Raw].load,
                                                                                        ReplaceString,
                                                                                        ReplaceWith,
                                                                                        )
                                if load != None:
                                    self.pcapfile[packet][Raw].load = load


                        self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                        self.pcapfile[packet][UDP].len = len(self.pcapfile[packet][UDP])
                        del self.pcapfile[packet][IP].chksum
                        del self.pcapfile[packet][UDP].chksum
                    else:
                        self.pcapfile[packet][UDP].dport = self.sport
                        self.pcapfile[packet][IP].src = self.dst
                        self.pcapfile[packet][Ether].src = self.dmac
                        self.pcapfile[packet][IP].dst = self.src
                        self.pcapfile[packet][Ether].dst = self.smac
                        for Replace in ReplaceList:
                            ReplaceString,ReplaceWith = Replace

                            #print 'trying to replace', ReplaceString, 'with ',  ReplaceWith
                            if self.pcapfile[packet].haslayer(Raw):
                                load = self.Replace_Raw_Data(self.pcapfile[packet][Raw].load,
                                                                                        ReplaceString,
                                                                                        ReplaceWith,
                                                                                        )
                                if load != None:
                                    self.pcapfile[packet][Raw].load = load


                        self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                        self.pcapfile[packet][UDP].len = len(self.pcapfile[packet][UDP])
                        del self.pcapfile[packet][IP].chksum
                        del self.pcapfile[packet][UDP].chksum
                elif self.pcapfile[packet].haslayer(IP):
                    print 'not TCP NOR UDP, just ip layer'

                    self.pcapfile[packet][IP].src = self.dst
                    self.pcapfile[packet][Ether].src = self.dmac
                    self.pcapfile[packet][IP].dst = self.src
                    self.pcapfile[packet][Ether].dst = self.smac
                    del self.pcapfile[packet][IP].chksum
                else:
                    print 'no ip layer in this pcap so lets not do anything'

            self.Packets.append(self.pcapfile[packet])
        return self.Packets

    def AlterPacketsBasic(self,
                          originalSource=None,
                          pcap = None):
        assert originalSource, 'must define an original source'
        assert os.path.exists(pcap), 'pcap path %s does not exist' %pcap
        self.pcapfile = rdpcap(pcap)

        print 'forming deltas'

        # print 'replace list', ReplaceList
        for packet in range(len(self.pcapfile)):
            if self.pcapfile[packet].haslayer(TCP):
                if self.pcapfile[packet][IP].src == originalSource:
                    self.pcapfile[packet][TCP].sport = self.sport
                    self.pcapfile[packet][IP].src = self.src
                    self.pcapfile[packet][Ether].src = self.smac
                    self.pcapfile[packet][TCP].dport = self.dport
                    self.pcapfile[packet][IP].dst = self.dst
                    self.pcapfile[packet][Ether].dst = self.dmac
                    self.pcapfile[packet][TCP].seq = self.pcapfile[packet][TCP].seq + deltaSeq
                    self.pcapfile[packet][TCP].ack = self.pcapfile[packet][TCP].ack + deltaAck
                    self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                    del self.pcapfile[packet][IP].chksum
                    del self.pcapfile[packet][TCP].chksum
                else:
                    self.pcapfile[packet][TCP].sport = self.dport
                    self.pcapfile[packet][IP].src = self.dst
                    self.pcapfile[packet][Ether].src = self.dmac
                    self.pcapfile[packet][TCP].dport = self.sport
                    self.pcapfile[packet][IP].dst = self.src
                    self.pcapfile[packet][Ether].dst = self.smac
                    self.pcapfile[packet][TCP].seq = self.pcapfile[packet][TCP].seq + deltaAck
                    self.pcapfile[packet][TCP].ack = self.pcapfile[packet][TCP].ack + deltaSeq
                    self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                    del self.pcapfile[packet][IP].chksum
                    del self.pcapfile[packet][TCP].chksum
            elif self.pcapfile[packet].haslayer(UDP):
                #print 'UDP'
                if self.pcapfile[packet][IP].src == originalSource:
                    self.pcapfile[packet][IP].src = self.src
                    self.pcapfile[packet][Ether].src = self.smac
                    self.pcapfile[packet][UDP].dport = self.dport
                    self.pcapfile[packet][IP].dst = self.dst
                    self.pcapfile[packet][Ether].dst = self.dmac
                    self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                    self.pcapfile[packet][UDP].len = len(self.pcapfile[packet][UDP])
                    del self.pcapfile[packet][IP].chksum
                    del self.pcapfile[packet][UDP].chksum
                else:
                    self.pcapfile[packet][UDP].dport = self.sport
                    self.pcapfile[packet][IP].src = self.dst
                    self.pcapfile[packet][Ether].src = self.dmac
                    self.pcapfile[packet][IP].dst = self.src
                    self.pcapfile[packet][Ether].dst = self.smac
                    self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                    self.pcapfile[packet][UDP].len = len(self.pcapfile[packet][UDP])
                    del self.pcapfile[packet][IP].chksum
                    del self.pcapfile[packet][UDP].chksum
            else:
                if self.pcapfile[packet].haslayer(IP):
                    print 'not TCP NOR UDP, just ip layer'
                    if self.pcapfile[packet][IP].src == originalSource:
                        self.pcapfile[packet][IP].src = self.src
                        self.pcapfile[packet][Ether].src = self.smac
                        self.pcapfile[packet][IP].dst = self.dst
                        self.pcapfile[packet][Ether].dst = self.dmac
                        self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                        del self.pcapfile[packet][IP].chksum
                    else:
                        self.pcapfile[packet][IP].src = self.dst
                        self.pcapfile[packet][Ether].src = self.dmac
                        self.pcapfile[packet][IP].dst = self.src
                        self.pcapfile[packet][Ether].dst = self.smac
                        self.pcapfile[packet][IP].len = len(self.pcapfile[packet][IP])
                        del self.pcapfile[packet][IP].chksum
                else:
                    print 'no ip layer in this pcap so lets not do anything'
            print 'adding packet', self.pcapfile[packet].show()
            self.Packets.append(self.pcapfile[packet])
        return self.Packets

    def Parse_Raw_Data(self,
                       Data,
                       removalstrlist=[0]):
        data = ''
        for Character in Data:
            if 31 < ord(Character) < 127:
                data += chr(ord(Character))
            elif ord(Character) in removalstrlist:
                pass
            else:
                data += '.'
        return data
    def AttachCharToData(self,
                         string,
                         insert = '\x00'):
        s = ''
        assert type(string) == str or type(string) == unicode, 'invalid string'
        for char in string:
            s += (insert+char)
        return s
    def Replace_Raw_Data(self,
                         Data,
                         StringSearch,
                         StringReplace,
                         AddChars = ['\x00'],
                         ):
        stringdata = self.Parse_Raw_Data(Data)

        if StringSearch in stringdata:
            #print 'found in string data'
            #first search for string in data
            #print 'searching for',  StringSearch, 'in', str(Data)
            if StringSearch in Data:
                #print 'found unmodified'
                #print 'setting %s to %s' %(Data, Data.replace(StringSearch, StringReplace))
                return Data.replace(StringSearch, StringReplace)
            print 'string not found.  looking from modified data'
            ##next look to see if string with added chars exists
            for AddChar in AddChars:
                getSearchString = self.AttachCharToData(StringSearch, insert=AddChar)
                #print 'searching for',  getSearchString, 'in', str(Data)
                if getSearchString in Data:
                    #print 'found modified'
                    getReplaceString = self.AttachCharToData(StringReplace, insert=AddChar)
                    return Data.replace(getSearchString, getReplaceString)
        return None
    def imapTest(self):
        print 'setting list'
        ReplaceList = [[imap_client_login,self.username],
                       ]
        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=imapSrc,
                          pcap=imapTemplate)
        return self.Packets
    def rshTest(self):
        print 'setting list'
        ReplaceList = [[rsh_client_name,self.username],
                       [rsh_server_name,self.servername],
                       ]
        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=rshSrc,
                          pcap=rshTemplate)
        return self.Packets
    def Pop3Test(self):
        print 'setting list'
        self.AlterPackets(ReplaceList = [[pop3_client_login, self.username]],
                          originalSource=pop3Src,
                          pcap=pop3Template)



        return self.Packets

    def otherTest(self):
        print 'altering packets'
        self.AlterPackets(originalSource=None,
                          pcap=SMBTemplate)
    def TelnetTest(self):
        print 'setting list'
        ReplaceList = [[TelnetName,self.username],
                       #[TelnetPassword,self.password],
                       [TelnetType, self.servername],
                       ]
        self.AlterPackets(ReplaceList = ReplaceList )
        return self.Packets

    def SMBTest(self):
        print 'setting list'
        ReplaceList = [[SMBName,self.username],
                       [SMBServer, self.servername],
                       ]
        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=SMBSrc,
                          pcap=SMBTemplate)
        return self.Packets
    def KRBTest(self):

        self.AlterPackets(ReplaceList = [],
                          originalSource=KRBSrc,
                          pcap=KRBTemplate)
        return self.Packets

    def SSHTest(self):

        self.AlterPackets(ReplaceList = [],
                          originalSource=SSHSrc,
                          pcap=SSHTemplate)
        return self.Packets

    def RadiusTest(self):
        print 'setting list'
        if len(self.username) == 10:
            ReplaceList = [[RadiusName,self.username],
                            ]
        else:
            ReplaceList = [[RadiusName,'namenot10c'],
                            ]
        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=RadiusSrc,
                          pcap=RadiusTemplate)
        return self.Packets

    def DiameterTest(self):
        print 'setting list'
        ReplaceList = [[DiameterUser,self.username],
                       ]
        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=DiameterSrc,
                          pcap=DiameterTemplate)
        return self.Packets

    def TDSTest(self):
        print 'setting list'
        ReplaceList = []
        if len(self.username) == 2:
            ReplaceList.append([TDSName,self.username])
        else:
            ReplaceList.append([TDSName,'10'])

        if len(self.servername) == 2:
            ReplaceList.append([TDSServer,self.servername])
        else:
            ReplaceList.append([TDSServer,'10'])

        if len(self.hostname) == 9:
            ReplaceList.append([TDSHost,self.hostname])
        else:
            ReplaceList.append([TDSHost,'hostnam10'])

        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=TDSSrc,
                          pcap=TDSTemplate)
        return self.Packets

    def MAPITest(self):
        print 'setting list'
        ReplaceList = []
        if len(self.username) == 8:
            ReplaceList.append([MapiUser,self.username])
        else:
            ReplaceList.append([MapiUser,'USERNAME'])

        if len(self.servername) == 20:
            ReplaceList.append([MapiName,self.servername])
        else:
            ReplaceList.append([MapiName,'%s@192.168.0.2' %ReplaceList[0][1]])


        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=MapiSrc,
                          pcap=MapiTemplate)
        return self.Packets
    def RLOGINTest(self):
        ReplaceList = []
        if self.hostname:
            ReplaceList.append([RLOGIN_client_host,self.hostname])
        if self.username:
            ReplaceList.append([RLOGIN_client_login,self.username])

        self.AlterPackets(ReplaceList = ReplaceList,
                          originalSource=RLOGINSrc,
                          pcap=RLOGINTemplate)
        return self.Packets




if __name__ == '__main__':
    print 'loading class'
    self = TemplateSupport()
    print 'setting variables'
    self.SetVariables(dmac = '11:22:33:44:55:66',
                      smac = '22:33:44:55:66:77',
                      TYPE = 'IPv4',
                      src = '1.1.1.1',
                      dst = '2.2.2.2',
                      sport = 1234,
                      dport = 23,
                      username = 'name',
                      password = 'password',
                      servername = 'servername')

    PACKETS = self.TelnetTest()
    print '# of packets', len(PACKETS)
    wrpcap('/tmp/telnettest.pcap',PACKETS)
