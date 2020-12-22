from Scapy_Control import *
from scapy.all import *
from SMB_COM import *

class SessionSetupAndX():

    def CreateNTLMInit(self,

                       ):
        NTLM = ''
        NTLM += stringtohex('NTLMSSP')  # identifyier +8 bytes=42bytes
        NTLM += '\x00'  # add to make 8 byts
        NTLM += HexCodeInteger(1, HexCodes=4)  # negotiate
        NTLM += HexCodeInteger(1611137557, HexCodes=4)  # negotiate flags

        # 24 to here
        offsetStart = 32
        # workstation domain  this is + 8 bytes so offset is always 32
        NTLM += HexCodeInteger(len(self.CLientDomain), HexCodes=2)  # len domain
        NTLM += HexCodeInteger(len(self.CLientDomain), HexCodes=2)  # len domain
        NTLM += HexCodeInteger(offsetStart, HexCodes=4)  # offset

        # workstation name
        NTLM += HexCodeInteger(len(self.ClientHost), HexCodes=2)  # len domain
        NTLM += HexCodeInteger(len(self.ClientHost), HexCodes=2)  # len domain
        NTLM += HexCodeInteger(offsetStart + len(self.CLientDomain), HexCodes=4)  # offset

        NTLM += stringtohex(self.CLientDomain)
        NTLM += stringtohex(self.ClientHost)
        NTLM += HexCodeInteger(0, HexCodes=2)  # fin

        ClientData = ''
        ClientData += padTextafter(self.clientnativeos) + '\x00\x00'
        ClientData += padTextafter(self.clientLanManager) + '\x00\x00'
        ClientData += padTextafter(self.CLientDomain) + '\x00\x00'



        return NTLM, ClientData

    def CreateNTLMNeedAuth(self,
                           ):

        NTLM = ''
        NTLM += stringtohex('NTLMSSP')  # identifyier +8 bytes=42bytes
        NTLM += '\x00'  # add to make 8 byts
        NTLM += HexCodeInteger(2, HexCodes=4)  # ntlmssp challenge


        # 24 to here
        offsetStart = 56
        # target domain  this is + 8 bytes so offset is always 32
        NTLM += HexCodeInteger(len(self.NBDomain), HexCodes=2)  # len domain
        NTLM += HexCodeInteger(len(self.NBDomain), HexCodes=2)  # len domain
        NTLM += HexCodeInteger(offsetStart, HexCodes=4)  # offset

        NTLM += '\x15\x02\x8a\x62' #negotiate flags
        self.ServerChallenge = RamdomRawData(size=8)
        NTLM += self.ServerChallenge  #NTLM ServerChallenge
        NTLM += HexCodeInteger(0, HexCodes=8)  # reserved




        SC = ''
        for k, v in self.ServerCredentials.iteritems():
            assert isinstance(v, dict), 'value in Server Credentials must be a dict but is %s' % type(v)
            SC += int_to_two_hex(v['type'])
            SC += int_to_two_hex(len(v['value']))
            SC += v['value']

        SC += int_to_four_hex(0)  # End Of List
        #print 'till now ntml len', len(NTLM)
        # TargetInfo
        NTLM += HexCodeInteger(len(SC), HexCodes=2)  # len ????
        NTLM += HexCodeInteger(len(SC), HexCodes=2)  # len ????
        NTLM += HexCodeInteger(56+len(self.NBDomain), HexCodes=4)  # offset

        NTLM += self.SetupNTMLVersion()
        NTLM += self.NBDomain  # target
        NTLM += SC


        ServerData = ''
        ServerData += self.servernativeos + '\x00\x00'
        ServerData += self.serverlanmanager + '\x00\x00'

        return NTLM, ServerData
    def createInitSecurityBlob(self,
                               ):


        NTLM,ClientData = self.CreateNTLMInit()
        #print 'NTLM len', len(NTLM)

        SecurityBlob = ''
        SecurityBlob += '\x60'
        SecurityBlob += HexCodeInteger(len(NTLM) + 31  #bytes of security blob after this and include ntlm
                                       , HexCodes=1)  # offset
        #  #48 is 72  is len of blob below this declaration
        SecurityBlob += '\x06\x06'  #OID is 6 len
        SecurityBlob += '\x2b\x06\x01\x05\x05\x02'  # oid for SPNEGO 1.3.6.5.5.2
        SecurityBlob += '\xa0'
        SecurityBlob += HexCodeInteger(len(NTLM) + 21  # bytes of security blob after this and include ntlm
                                       , HexCodes=1)  # offset
        SecurityBlob += '\x30'
        SecurityBlob += HexCodeInteger(len(NTLM) + 19  # bytes of security blob after this and include ntlm
                                       , HexCodes=1)  # offset
        SecurityBlob += '\xa0\x0e'  # ??? 0x0e = 14
        SecurityBlob += '\x30\x0c'  # ??? 0x0c is 12

        SecurityBlob += '\x06\x0a'  # OID is 10 len
        SecurityBlob += '\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # oid for NTLMSSP 1.3.6.1.4.1.311.2.2.10

        SecurityBlob += '\xa2'
        SecurityBlob+=HexCodeInteger(len(NTLM) +1,  #bytes of security blob after this and include ntlm
                                      HexCodes=1)  #
        SecurityBlob += '\x04'
        SecurityBlob += HexCodeInteger(len(NTLM) -1,  #bytes of security blob after this and include ntlm
                                      HexCodes=1)  #
        SecurityBlob += NTLM

        #section begin seting
        return SecurityBlob, ClientData



    def createAuthSecurityBlob(self,
                                   ):


        NTLM, ClientData = self.createNTLMauth()
        #print 'NTLM len', len(NTLM)
        #print 'len client data', len(ClientData)

        SecurityBlob = ''
        SecurityBlob += '\xa1\x81'  # SPNEGO
        SecurityBlob += HexCodeInteger(len(NTLM) + 9, HexCodes=1)  #
        SecurityBlob += '\x30\x81'
        SecurityBlob += HexCodeInteger(len(NTLM) + 6, HexCodes=1)
        SecurityBlob += '\xa2\x81'
        SecurityBlob += HexCodeInteger(len(NTLM) + 3, HexCodes=1)
        SecurityBlob += '\x04\x81'
        SecurityBlob += HexCodeInteger(len(NTLM), HexCodes=1)
        SecurityBlob += NTLM

        # section begin seting
        return SecurityBlob, ClientData

    def createNTLMauth(self):
        NTLM = ''
        NTLM += stringtohex('NTLMSSP')  # identifyier +8 bytes=42bytes
        NTLM += '\x00'  # add to make 8 byts
        NTLM += HexCodeInteger(3, HexCodes=4)  # ntlmssp auth

        # get the number of keys in connection Credentials and allocate space

        ClientCredentials = {
            'NTMLChallenge': RamdomRawData(size=8),
            'NTMLResponse': RamdomRawData(size=24),
            'CDoman': padTextafter(self.CLientDomain),
            'CUser': padTextafter(self.ClientUser),
            'CHost': padTextafter(self.ClientHost),
            'SessionKey': RamdomRawData(size=16),
        }

        order = {'NTMLChallenge': {'so': 0, 'ro': 0},
                 'NTMLResponse': {'so': 1, 'ro': 1},
                 'CDoman': {'so': 2, 'ro': 2},
                 'CUser': {'so': 3, 'ro': 3},
                 'CHost': {'so': 4, 'ro': 4},
                 'SessionKey': {'so': 5, 'ro': 5},
                 }

        # populate order with key sizes and values
        sizeofoffset= 8*len(self.ClientCredentials)
        #offset = '' + sizeoffset + ''
        offset = sizeofoffset +  16
        for key in order.keys():
            value = self.ClientCredentials.get(key)
            if value:
                order[key]['len'] = len(value)
                order[key]['value'] = value

        #now create values
        NTMLRAW = ''
        for i in range(len(order)):
            for k, v in order.iteritems():
                if v['ro'] == i:
                    order[k]['offset'] = offset
                    offset += len(order[k]['value'])
                    NTMLRAW += order[k]['value']

        # lets create the size order
        for i in range(len(order)):
            for k, v in order.iteritems():
                if v['so'] == i:
                    NTLM += int_to_two_hex(v.get('len'))
                    NTLM += int_to_two_hex(v.get('len'))
                    NTLM += int_to_four_hex(v.get('offset'))

        NTLM += '\x15\x02\x08\x60'  # negotiate flags
        NTLM += NTMLRAW
        NTLM += HexCodeInteger(0, HexCodes=1)  #extra fin

        ClientData = ''
        ClientData += padTextafter(self.clientnativeos)
        ClientData += padTextafter(self.clientLanManager)
        ClientData += padTextafter(self.CLientDomain)
        ClientData += HexCodeInteger(0, HexCodes=2)  # extra fin

        return NTLM, ClientData


    def createNeedAuthSecurityBlob(self):
        NTLM, ServerData = self.CreateNTLMNeedAuth()
        #print 'len NTLM', len(NTLM)
        #print 'len ServerData', len(ServerData)
        SecurityBlob = ''
        SecurityBlob += '\xa1\x81'#  SPNEGO
        SecurityBlob += HexCodeInteger(len(NTLM) +28, HexCodes=1)  #
        SecurityBlob += '\x30\x81'
        SecurityBlob += HexCodeInteger(len(NTLM) +25, HexCodes=1)
        SecurityBlob += '\xa0\x03\x0a\x01'  #276?
        SecurityBlob += HexCodeInteger(1, HexCodes=1)  #accept incomplete
        SecurityBlob += '\xa1\x0c'  #oc is len 12
        SecurityBlob += '\x06\x0a'  #0a is len of oid
        SecurityBlob += '\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # oid for NTLMSSP Microsoft NTLM security support provider 1.3.6.1.4.1.311.2.2.10
        SecurityBlob += '\xa2\x81'
        SecurityBlob += HexCodeInteger(len(NTLM) +3, HexCodes=1)
        SecurityBlob += '\x04\x81'
        SecurityBlob += HexCodeInteger(len(NTLM), HexCodes=1)
        SecurityBlob += NTLM

        # section begin seting
        return SecurityBlob, ServerData

    def SetupNTMLVersion(self,
                         **kwargs):


        raw = ''
        raw += HexCodeInteger(kwargs.get('majorversion') or 6, HexCodes=1)  # major version 6 +1=65bytes
        raw += HexCodeInteger(kwargs.get('minorversion') or 0, HexCodes=1)  # miner version 0 +1=66bytes
        raw += int_to_two_hex(kwargs.get('buildnumber') or 5231)  # build numer 6001 +2=70bytes
        raw += '\x00\x00\x00'  # ? +3=73bytes
        raw += HexCodeInteger(kwargs.get('ntmlrevistion') or 15, HexCodes=1)  # NTML Current Revision 15 +1=746ytes

        return raw




    def SessionSetupandxInitRequest(self,
                                    Flow='SMB',
                                    **kwargs):


        raw = self.SMBHeader(command=SMB_COM_SESSION_SETUP_ANDX,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             )

        raw += HexCodeInteger(12, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(12288, HexCodes=2)  # mmax buffer count
        raw += HexCodeInteger(50, HexCodes=2)  # mmax MPx count
        raw += HexCodeInteger(1, HexCodes=2)  # VC number
        raw += HexCodeInteger(0, HexCodes=4)  # session key

        SecurityBlob, ClientCred = self.createInitSecurityBlob()
        #print 'secblob', len(SecurityBlob)
        #print 'client data', len(ClientCred)
        # raw += HexCodeInteger(len(SecurityBlob), HexCodes=2)  # len security blob
        raw += HexCodeInteger(len(SecurityBlob) - 1, HexCodes=2)  # len security blob
        raw += HexCodeInteger(0, HexCodes=4)  # reserved
        raw += HexCodeInteger(2147738621, HexCodes=4)  # capabilities

        raw += int_to_two_hex(len(SecurityBlob) + len(ClientCred))  # byte count
        raw += SecurityBlob + ClientCred

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def SessionSetupandxNeedAuthResopnse(self,
                                         Flow='SMB'):


        raw = self.SMBHeader(command=SMB_COM_SESSION_SETUP_ANDX,
                             flags=136,
                             flags2=51203,
                             ntstatus=3221225494,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             )

        raw += HexCodeInteger(4, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(412, HexCodes=2)  # offset   #dont know why 412
        raw += HexCodeInteger(0, HexCodes=2)  # action 0-->not logged in

        SecurityBlob, ServerData = self.createNeedAuthSecurityBlob()
        #print 'len secblob', len(SecurityBlob)
        #print 'len ServerData', len(ServerData)
        raw += HexCodeInteger(len(SecurityBlob), HexCodes=2)  # blob len
        raw += HexCodeInteger(len(SecurityBlob) + len(ServerData), HexCodes=2)  # byte count
        raw += SecurityBlob + ServerData

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def SessionSetupandxAuthRequest(self,
                                     Flow ='SMB'):
        raw = self.SMBHeader(command=SMB_COM_SESSION_SETUP_ANDX,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             )

        raw += HexCodeInteger(12, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # resered
        raw += HexCodeInteger(0, HexCodes=2)  # andx offset
        raw += HexCodeInteger(12288, HexCodes=2)  # max buffer
        raw += HexCodeInteger(50, HexCodes=2)  # mx mpx count
        raw += HexCodeInteger(1, HexCodes=2)  # vc number
        raw += HexCodeInteger(0, HexCodes=4)  # session key

        SecurityBlob, ClientCred = self.createAuthSecurityBlob()
        #print 'secblob rq', len(SecurityBlob)
        #print 'client data rq', len(ClientCred)

        raw += HexCodeInteger(len(SecurityBlob), HexCodes=2)  # security blog len
        raw += HexCodeInteger(0, HexCodes=4)  # reserved
        raw += HexCodeInteger(0x8003e3fd, HexCodes=4)  # capabilities  0x8003e3fd
        raw += HexCodeInteger(len(SecurityBlob) + len(ClientCred), HexCodes=2)  # byte count

        raw += SecurityBlob+ClientCred

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)


    def CreateFinalSecurityBlob(self):
        SecurityBlob = ''
        SecurityBlob += '\xa1\x07\x30\x05\xa0\x03\x0a\x01'
        SecurityBlob += HexCodeInteger(0, HexCodes=1)  # accept completed

        ServerData = ''
        ServerData += self.servernativeos + '\x00\x00'
        ServerData += self.serverlanmanager + '\x00\x00'

        return SecurityBlob, ServerData
    def SessionSetupandxFinalResopnse(self,
                                         Flow='SMB'):


        raw = self.SMBHeader(command=SMB_COM_SESSION_SETUP_ANDX,
                             flags=136,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             )

        raw += HexCodeInteger(4, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(242, HexCodes=2)  # offset   #dont know why 412
        raw += HexCodeInteger(0, HexCodes=2)  # action 0-->not logged in

        SecurityBlob, ServerData = self.CreateFinalSecurityBlob()
        #print 'len secblob', len(SecurityBlob)
        #print 'len ServerData', len(ServerData)
        raw += HexCodeInteger(len(SecurityBlob), HexCodes=2)  # blob len
        raw += HexCodeInteger(len(SecurityBlob) + len(ServerData), HexCodes=2)  # byte count
        raw += SecurityBlob + ServerData

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)
