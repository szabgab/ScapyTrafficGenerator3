import time
from SMB_COM import *
from Scapy_Control import *
from scapy.all import *
class SMBNegotiate():
    def NegotiateRequest(self,
                         Flow='SMB',
                         dialects = ['PC NETWORK PROGRAM 1.0',
                                     'MICROSOFT NETWORKS 1.03',
                                     'MICROSOFT NETWORKS 3.0',
                                     'LANMAN1.0',
                                     'Windows for Workgroups 3.1a',
                                     'LM1.2X002',
                                     'DOS LANMAN2.1',
                                     'LANMAN2.1',
                                     'Samba',
                                     'NT LANMAN 1.0',
                                     'NT LM 0.12'],
                         **kwargs):

        DIALECTS = ''
        for d in dialects:
            DIALECTS += '\x02%s\x00' %d
        #hexdump(DIALECTS)
        raw = self.SMBHeader(command=SMB_COM_NEGOTIATE,
                              flags=8,
                              flags2=51267,
                              mid=self.MID)



        raw += '\x00'  # word count
        raw += int_to_two_hex(len(DIALECTS))  # byte count
        raw += DIALECTS
        raw = self.add_raw_to_nb(raw=raw)
        #print '***'
        #hexdump(raw)
        #print '***'
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)


    def NegotiateResponse(self,
                          selectedIndex=10,
                          Flow='SMB',
                          **kwargs):


        raw = self.SMBHeader(command=SMB_COM_NEGOTIATE,
                        flags=136,
                        flags2=51267,
                        mid=self.MID,
                        #pid=self.PID,
                        #uid=self.UID,
                             )


        raw += HexCodeInteger(17, HexCodes=1) #word count
        raw += int_to_two_hex(selectedIndex)  # selected index '\x0a\x00' #NT LM 0.12
        raw += HexCodeInteger(3, HexCodes=1)  # security mode
        raw += int_to_two_hex(10)  # max mpx count
        raw += int_to_two_hex(1)  # Max VCS
        raw += int_to_four_hex(4356)  # max buffer size
        raw += int_to_four_hex(65536)  # max raw buffer
        raw += int_to_four_hex(0)   # session key'
        raw += int_to_four_hex(2147738621)  # capabilities #0x8003e3fd
        raw += HexCodeInteger(int(time.time()), HexCodes=8, Swap=False)  # system time
        raw += int_to_two_hex(0)  # timezone (timezone in minutes (just try 0)
        raw += HexCodeInteger(0, HexCodes=1) # key length


        SecurityBlob=self.createNegotiateSecurityBlob()
        #hexdump(SecurityBlob)
        #hexdump(int_to_two_hex(len(SecurityBlob) + len(self.GUID)))
        raw += int_to_two_hex(len(SecurityBlob) + len(self.GUID))  # len security blob + guid len
        raw += self.GUID  # Server GUID
        raw += SecurityBlob  # SecurityBlob

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def createNegotiateSecurityBlob(self):


        SecurityBlob = ''
        SecurityBlob += '\x60\x3e' #3e is 62  is len of blob below this declaration
        SecurityBlob += '\x06\x06'  #OID is 6 len
        SecurityBlob += '\x2b\x06\x01\x05\x05\x02'  # oid for SPNEGO 1.3.6.5.5.2
        SecurityBlob += '\xa0\x34'    #0x34 is 52
        SecurityBlob += '\x30\x32'  #??? 32 is 50
        SecurityBlob += '\xa0\x30'  # 0x34 is 48
        SecurityBlob += '\x30\x2e'  # ??? e2 = 46

        SecurityBlob += '\x06\x09'  # OID kerb is 9
        SecurityBlob += '\x2b\x86\x48\x82\xf7\x12\x01\x02\x02'  # oid for MS KRB5 1.2.840.48048.1.2.2
        SecurityBlob += '\x06\x09'  # OID is 9 len
        SecurityBlob += '\x2b\x86\x48\x86\xf7\x12\x01\x02\x02'  # oid for KRB5 1.2.840.113554.1.2.2
        SecurityBlob += '\x06\x0a'  # OID is 10 len
        SecurityBlob += '\x2b\x86\x48\x86\xf7\x12\x01\x02\x02\x03'  # oid for KRB5 user to user 1.2.840.113554.1.2.2.3
        SecurityBlob += '\x06\x0a'  # OID is 10 len
        SecurityBlob += '\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # oid for NTLMSSP 1.3.6.1.4.1.311.2.2.10
        return SecurityBlob