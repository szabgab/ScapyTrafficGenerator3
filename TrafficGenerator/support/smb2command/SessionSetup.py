from Scapy_Control import *
from scapy.all import *
from NBSession import *


class SessionSetup(NBSession):
    def SetupRequest(self,
                     GSSAPILEN,
                     **kwargs):
        raw = ''
        raw += int_to_two_hex(kwargs.get('size') or 25)  # structure size
        raw += HexCodeInteger(kwargs.get('flags') or 0, HexCodes=1)  # \x00  #flags
        raw += HexCodeInteger(kwargs.get('smode') or 1, HexCodes=1)  # '\x01'  # security mode
        raw += int_to_four_hex(kwargs.get('capabilities') or 0)  # capabilities
        raw += int_to_four_hex(kwargs.get('channel') or 0)  # channel 0 none
        raw += int_to_two_hex(kwargs.get('offset') or 88)  # offset
        raw += int_to_two_hex(GSSAPILEN) #was 74 # legth of GSSAPI
        raw += int_to_eight_hex(kwargs.get('psid') or (0))  # Previous session id

        return raw

    def SetupResponse(self,
                      GSSAPILEN,
                      **kwargs):
        raw = ''
        raw += int_to_two_hex(kwargs.get('size') or 9)  # structure size
        raw += HexCodeInteger(kwargs.get('flags') or 0, HexCodes=2)  # \x00  #flags
        raw += int_to_two_hex(kwargs.get('offset') or 72)  # offset
        raw += int_to_two_hex(GSSAPILEN)  # was 74 # legth of GSSAPI

        return raw
    #for init setup
    def GSSAPI_NTLM_Negotiate(self,
                              GSSSize):
        raw = '\xa1\x81'  # start
        raw += HexCodeInteger(GSSSize-3, HexCodes=1, Swap=False)
        #token
        raw += '\x30\x81'  # 'version?'
        raw += HexCodeInteger(GSSSize-6, HexCodes=1, Swap=False)
        raw += '\xa0\x03\x0a\x01'  #token?
        raw += HexCodeInteger(1, HexCodes=1) # 1 for accept incocomlete
        raw += '\xa1\x0c\x06\x0a'  #? b4 oid
        raw += '\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # oid for NTLM Security Support Provider  +10=30bytes
        raw += '\xa2\x81'
        raw += HexCodeInteger(GSSSize - 28, HexCodes=1, Swap=False)
        raw += '\x04\x81'
        raw += HexCodeInteger(GSSSize - 31, HexCodes=1, Swap=False)
        return raw

    # for init setup
    def GSSAPI_NTLM_Negotiate_Complete(self):
        raw = ''
        raw += '\xa1\x07'  # simple proteced negotiaction
        raw += '\x30\x05\xa0\x03\x0a\x01'  # negTokenTarg
        raw += HexCodeInteger(0, HexCodes=1)  # accept-completed
        return raw

    def GSSAPI_NTLM_AUTH(self,
                         GSSSize,
                          negToken='\x30\x82\x01\x40\xa2\x82\x01\x3c\x04\x82\x01\x38',
                          servicepointer='\xa2\x82\x01\x92\x04\x82\x01\x8e', #for ntlm
                          **kwargs):
        raw = '\xa1\x82' #start
        raw += int_to_two_hex(GSSSize -4, Swap=False)

        #token
        raw += '\x30\x82'#'version?'
        raw += int_to_two_hex(GSSSize -8, Swap=False)
        raw += '\xa2\x82' #mech?
        raw += int_to_two_hex(GSSSize - 12, Swap=False)
        raw += '\x04\x82' #?
        raw += int_to_two_hex(GSSSize - 16, Swap=False)
        #raw += HexCodeInteger(kwargs.get('negresult') or 1, HexCodes=1)  # neg Result 1 = accept-incomplete
        #raw += servicepointer
        return raw

    def NTML_CHALLENGE(self,
                       **kwargs):
        #raw = ''
        #raw += int_to_eight_hex(kwargs.get('challenge') or 0)  # NTML ClientChallenge (lan response start)
        #raw += HexCodeInteger(kwargs.get('lanext') or 0, HexCodes=16)  # Lan Manager Response ext
        #raw='\x5f\xd3\x51\x0c\xd2\xee\x01\xb6\x91\x12\xa0\xd3\xd6\x89\x58\xa1\x52\xe9\xe9\x75\x19\x8c\x0a\x28'
        #return raw
        #return HexCodeInteger(0,HexCodes=24)
        return RamdomRawData(size=24)

    def NTLM_SERVER_CHALLENGE(self,
                              #NTLMSIZE,
                              target=None,
                              **kwargs):

        assert target != None, 'must specify target in ntml server challenge'
        raw = ''
        raw += stringtohex('NTLMSSP')  # identifyier +8 bytes=42bytes
        raw += '\x00'  # add to make 8 byts
        raw += int_to_four_hex(2)  # 1 is NTLMSSP_CHALLENGE+4=46bytes
        raw += int_to_two_hex(len(target))
        raw += int_to_two_hex(len(target))
        raw += int_to_four_hex(56)
        raw += '\x15\x82\x8a\x15'  #flags
        raw += RamdomRawData(size=8) #server challenge
        raw += int_to_eight_hex(0) #reserved
        raw += int_to_two_hex(104)
        raw += int_to_two_hex(104)
        raw += int_to_four_hex(56 + len(target))


        return raw

    def NTMLv2_Response(self,
                        #NTPROOF=RamdomRawData(size=16),#'\xb7\xc1\x57\xdf\x06\x26\x89\x8c\x16\xf0\xf2\xb2\x25\xa2\x27\x90',
                        NTLMSIZE = 0,
                        target=None,
                        ServerCredentials = None,
                        **kwargs):
        raw = ''
        if target:  #server challenge
            raw += self.NTLM_SERVER_CHALLENGE(#NTLMSIZE,
                                              target=target,
                                              **kwargs)
            raw += self.SetupNTMLVersion(**kwargs)
            #now target
            raw += target
        else: #TPROF
            raw += self.NTLMv2Response_Proof()
            #version info
                #raw += NTPROOF  # NTPROOF STR
        if ServerCredentials:
            assert isinstance(ServerCredentials, dict), 'ConnectionCredentials needs to be a dict but is %s' % type(ServerCredentials)


            for k,v in ServerCredentials.iteritems():
                assert isinstance(v,dict), 'value in Server Credentials must be a dict but is %s' %type(v)
                raw += int_to_two_hex(v['type'])
                raw += int_to_two_hex(len(v['value']))
                raw += v['value']

            raw += int_to_four_hex(0) #End Of List


        return raw

    def NTLMSSP_Setup(self,
                          NTLMMESSAGETYPE = 1, #this is Negotiate
                          flags = '\x97\x82\x08\xe2',  #flags (default for negotiate)
                          ClientCredentials = None,
                          ServerCred = None,
                          MIC = '\xb3\x60\x2d\xa6\xa7\x98\x7c\xa0\xed\x61\x73\x69\x9e\x1c\x72\xea',
                          **kwargs):
        raw = ''
        raw += stringtohex('NTLMSSP') #identifyier +8 bytes=42bytes
        raw += '\x00'  #add to make 8 byts
        raw += int_to_four_hex(NTLMMESSAGETYPE)  # 1 is NTLMSSP_NEGOTIATE +4=46bytes

        if ServerCred:
            raw += ServerCred

        if ClientCredentials == None and ServerCred == None:
            #dont set credentials because just initiating negotiate
            raw += '\x00\x00\x00\x00\x00\x00\x00\x00'  # calling Workstationdomain null +8 = 58 bytes
            raw += '\x00\x00\x00\x00\x00\x00\x00\x00'  # calling worskstation name null +8=64 bytes
            raw += self.SetupNTMLVersion(**kwargs)
            return raw


        if ClientCredentials:
            assert isinstance(ClientCredentials, dict), 'ConnectionCredentials needs to be a dict but is %s' % type(ClientCredentials)

            #get the number of keys in connection Credentials and allocate space
            sizeoffset = len(ClientCredentials)*8
            order = {'NTMLChallenge': {'so': 0, 'ro':0},
                    'NTMLv2_Response': {'so': 1, 'ro':1},
                     'CDoman': {'so': 2, 'ro':2},
                     'CUser': {'so': 3, 'ro':3},
                     'CHost': {'so': 4, 'ro':4},
                     'SessionKey': {'so': 5, 'ro':5},
            }

            #populate order with key sizes and values
            for key in order.keys():
                value = ClientCredentials.get(key)
                if value:
                    order[key]['len']= len(value)
                    order[key]['value']= value


            offset = len(raw) + sizeoffset + len(flags)
            NTMLRAW = ''
            for i in range(len(order)):
                for k,v in order.iteritems():
                    if v['ro'] == i:
                        order[k]['offset'] = offset
                        offset += len(order[k]['value'])
                        NTMLRAW += order[k]['value']

            #lets create the size order
            #lets create the size order
            for i in range(len(order)):
                for k, v in order.iteritems():
                    if v['so'] == i:
                        raw += int_to_two_hex(v.get('len'))
                        raw += int_to_two_hex(v.get('len'))
                        raw += int_to_four_hex(v.get('offset'))

            raw += flags
            raw += NTMLRAW



        return raw
    def finalUnknownMechliststuff(self,
                                  unknown = '\xa3\x12\x04\x10',
                                  **kwargs):
        raw = ''
        raw += unknown  # have no idea what these bytes are doing....

        raw += HexCodeInteger(kwargs.get('mechListMIC') or 1, HexCodes=16)  # last... mechListMIC
        return raw

    def SetupNTMLVersion(self,
                         **kwargs):
        raw = ''
        raw+=HexCodeInteger(kwargs.get('majorversion') or 6, HexCodes=1) # major version 6 +1=65bytes
        raw += HexCodeInteger(kwargs.get('minorversion') or 0, HexCodes=1) # miner version 0 +1=66bytes
        raw += int_to_two_hex(kwargs.get('buildnumber') or 6001)  # build numer 6001 +2=70bytes
        raw += '\x00\x00\x00'  # ? +3=73bytes
        raw += HexCodeInteger(kwargs.get('ntmlrevistion') or 15, HexCodes=1)  # NTML Current Revision 15 +1=746ytes

        return raw

    def NTLMv2Response_Proof(self,
                             **kwargs):
        raw = ''
        raw += RamdomRawData(size=16)  #proof string
        raw += HexCodeInteger(1, HexCodes=1)  # response version
        raw += HexCodeInteger(1, HexCodes=1)  # hi response version
        raw += HexCodeInteger(0, HexCodes=6)  # z
        raw += HexCodeInteger(int(time.time() * 1000), HexCodes=8) # timestamp
        raw += RamdomRawData(size=8)#ClientChallenge
        raw += HexCodeInteger(0, HexCodes=4)  # z
        return raw

    def SessionSetupSMB2Request_NTMSSP_NEGOTIATE(self,
                                                 Flow='SMB',
                                                 **kwargs):

        raw = self.SMB2Header(credit=0,
                              credits=8,
                              command=1,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              )

        ### Session Setup And Request
        raw += int_to_two_hex(25)  # structure size
        raw += HexCodeInteger(0, HexCodes=1)  # \x00  #flags
        raw += HexCodeInteger(1, HexCodes=1)  # '\x01'  # security mode
        raw += int_to_four_hex(1)  # capabilities
        raw += int_to_four_hex(0)  # channel 0 none
        # raw += int_to_four_hex(8)  # session id



        ### Security blob
        raw += int_to_two_hex(88)  # offset
        raw += int_to_two_hex(74)  # legth of GSSAPI
        raw += int_to_eight_hex(0)  # Previous session id

        # raw += '\x00\x00\x00\x00\x00\x00\x00\x00'  # dont know may not do anything

        ###GSS-API (Generic Security Service Application Protocol Interface  (the value of this adds up to legth of GSSAPI
        raw += '\x60\x48\x06\x06'  # i have no idea what this is  +4=4 bytes
        raw += '\x2b\x06\x01\x05\x05\x02'  # oid for simple protected negotiation  +6=10bytes
        raw += '\xa0\x3e'  # simp protected neg start ? maybe' +2=12 bytes
        raw += '\x30\x3c\xa0\x0e\x30\x0c'  # negTokenInit +6 = 18 bytes
        raw += '\x06\x0a'  # 0a is 10 is length of NTLMSSP
        raw += '\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # oid for NTLM Security Support Provider  +10=30bytes

        raw += '\xa2\x2a\x04\x28'  # b4 mech ?? +4 =34
        ###Mechtocken
        raw += stringtohex('NTMLSSP')  # identifyier +8 bytes=42bytes
        raw += '\x00'  # finish ntmlssp
        raw += int_to_four_hex(1)  # 1 is NTLMSSP_NEGOTIATE +4=46bytes
        raw += '\x97\x82\x08\xe2'  # Negotiate Flages +4 = 50 bytes
        raw += '\x00\x00\x00\x00\x00\x00\x00\x00'  # calling Workstationdomain null +8 = 58 bytes
        raw += '\x00\x00\x00\x00\x00\x00\x00\x00'  # calling worskstation name null +8=64 bytes
        raw += '\x06'  # major version 6 +1=65bytes
        raw += '\x00'  # miner version 0 +1=66bytes
        raw += int_to_two_hex(6001)  # build number 6001 +2=70bytes
        raw += '\x00\x00\x00'  # ? +3=73bytes
        raw += '\0f'  # NTML Current Revision 15 +1=746ytes

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)


    def SessionSetupSMB2ResponceNeedAuthenticataion(self,
                                                    Flow='SMB',
                                                    **kwargs):
        raw = self.SMB2Header(credit=1,
                              credits=8,
                              flags=1,
                              ntstatus=3221225494,  # NEED AUTHENTICATAION
                              command=1,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              )

        NTLM = {
            'nbd': {'type': 2, 'value': padTextafter(self.NBDomain)},
            'nbc': {'type': 1, 'value': padTextafter(self.NBComp)},
            'dnsd': {'type': 4, 'value': padTextafter(self.DNSDoman)},
            'dnsn': {'type': 3, 'value': padTextafter(self.DNSCOMP)},
            'dnst': {'type': 5, 'value': padTextafter(self.DNSTREE)},
            'timestamp': {'type': 7, 'value': HexCodeInteger(int(time.time() * 1000), HexCodes=8)},
        }
        target = padTextafter(self.NBDomain)
        NTLM = self.NTMLv2_Response(  # NTLMSIZE,
            ServerCredentials=NTLM,
            target=target)

        gss = self.GSSAPI_NTLM_Negotiate(len(NTLM) + 31)

        gss += NTLM

        raw += self.SetupResponse(len(gss)
                                  )

        raw += gss
        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)


    def SessionSetupSMB2RequestUser(self,
                                    Flow='SMB',
                                    **kwargs):
        raw = self.SMB2Header(credit=1,
                              credits=30,
                              command=1,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              )

        ServerCredentials = {
            'nbd': {'type': 2, 'value': padTextafter(self.NBDomain)},
            'nbc': {'type': 1, 'value': padTextafter(self.NBComp)},
            'dnsd': {'type': 4, 'value': padTextafter(self.DNSDoman)},
            'dnsn': {'type': 3, 'value': padTextafter(self.DNSCOMP)},
            'dnst': {'type': 5, 'value': padTextafter(self.DNSTREE)},
            'timestamp': {'type': 7, 'value': HexCodeInteger(int(time.time() * 1000), HexCodes=8)},
            # 'flags': {'type': 6, 'value': int_to_four_hex(2)},
        }

        ClientCredentials = {'NTMLChallenge': RamdomRawData(size=8) + (HexCodeInteger(0, HexCodes=16)),  # NTMLChallenge
                             'NTMLv2_Response': RamdomRawData(size=24),
                             'CDoman': padTextafter(self.CLientDomain),
                             'CUser': padTextafter(self.ClientUser),
                             'CHost': padTextafter(self.ClientHost),
                             'SessionKey': self.SessionKey,
                             }

        NTML = self.NTLMSSP_Setup(NTLMMESSAGETYPE=3,  # for NTLMSSP_AUTH
                                  flags='\x15\x82\x08\x60',
                                  ClientCredentials=ClientCredentials)
        gss = self.GSSAPI_NTLM_AUTH(GSSSize=len(NTML) + 16,
                                    )
        gss += NTML
        raw += self.SetupRequest(len(gss))

        raw += gss

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)


    def SessopmSetupResponseFinal(self,
                                  Flow='SMB',
                                  **kwargs):
        raw = self.SMB2Header(credits=8,
                              flags=1,
                              command=1,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              )
        gss = self.GSSAPI_NTLM_Negotiate_Complete()
        raw += self.SetupResponse(len(gss))
        raw += gss

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)
