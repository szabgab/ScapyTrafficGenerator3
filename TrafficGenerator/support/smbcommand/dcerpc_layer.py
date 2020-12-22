from Scapy_Control import *
class dcerpc_layer():
    def dcerpc_bind_request(self,
                            version = 5,
                       minorversion = 0,
                       packettype = 11,  #11 for bind
                       flags = 3,
                       fraglen=72,
                       Authlen=0,
                       MaxXmitFrag=4280,
                            MaxRexFrag=4280,
                       AssocGroup=0,
                            numCtxItems=1,
                            numbTransItems=1,
                       ContextId=0,
                            SVCCTLUUID='\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03',
                            INTVer = 2,
                            INTVermin =0,
                            TransSyntax='\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60',
                            TransVer=2,
                            TransVermin=0,


                       **kwargs):
        raw = ''
        raw += HexCodeInteger(version, HexCodes=1)  # version
        raw += HexCodeInteger(minorversion, HexCodes=1)  # minor version
        raw += HexCodeInteger(packettype, HexCodes=1)  # packet type
        raw += HexCodeInteger(flags, HexCodes=1)  # packet flags
        raw += '\x10\x00\x00\x00'  # data representation  ??
        raw += HexCodeInteger(fraglen, HexCodes=2)
        raw += HexCodeInteger(Authlen, HexCodes=2)
        raw += HexCodeInteger(self.CallID, HexCodes=4)
        raw += HexCodeInteger(MaxXmitFrag, HexCodes=2)
        raw += HexCodeInteger(MaxRexFrag, HexCodes=2)
        raw += HexCodeInteger(AssocGroup, HexCodes=4)
        raw += HexCodeInteger(numCtxItems, HexCodes=1)
        raw += HexCodeInteger(0, HexCodes=3)  #pad?
        raw += HexCodeInteger(ContextId, HexCodes=2)
        raw += HexCodeInteger(numbTransItems, HexCodes=1)
        raw += HexCodeInteger(0, HexCodes=1)  # pad?
        if SVCCTLUUID:
            raw += SVCCTLUUID
        else:
            raw += RamdomRawData(size=16)
        raw += HexCodeInteger(INTVer, HexCodes=2)
        raw += HexCodeInteger(INTVermin, HexCodes=2)
        if TransSyntax:
            raw += TransSyntax
        else:
            raw += RamdomRawData(size=16)
        raw += HexCodeInteger(TransVer, HexCodes=2)
        raw += HexCodeInteger(TransVermin, HexCodes=2)



        return raw
    def dcerpc_request(self,
                       version = 5,
                       minorversion = 0,
                       packettype = 0,  #0 for request
                       flags = 3,
                       fraglen=80,
                       Authlen=0,
                       AllocHint=56,
                       ContextID=0,
                       **kwargs):
        #print 'opnum is now', self.Opnum
        raw = ''
        raw += HexCodeInteger(version, HexCodes=1)  # version
        raw += HexCodeInteger(minorversion, HexCodes=1)  # minor version
        raw += HexCodeInteger(packettype, HexCodes=1)  # packet type
        raw += HexCodeInteger(flags, HexCodes=1)  # packet flags
        raw += '\x10\x00\x00\x00'  # data representation  ??
        #print 'fraglen', self.svcctSize+2
        if self.subcommand == 0x26:
            raw += HexCodeInteger(self.svcctSize+24, HexCodes=2)
        else:
            raw += HexCodeInteger(fraglen, HexCodes=2)
        #raw += HexCodeInteger(self.expectedSize, HexCodes=2)
        raw += HexCodeInteger(Authlen, HexCodes=2)
        raw += HexCodeInteger(self.CallID, HexCodes=4)
        if self.subcommand == 0x26:
            raw += HexCodeInteger(self.svcctSize, HexCodes=4)
        else:
            raw += HexCodeInteger(AllocHint, HexCodes=4)
        raw += HexCodeInteger(ContextID, HexCodes=2)
        raw += HexCodeInteger(self.Opnum, HexCodes=2)
        self.dcerpclen=len(raw)
        #print 'dceprplen', self.dcerpclen
        return raw

    def dcerpc_response(self,
                        version = 5,
                       minorversion = 0,
                       packettype = 2,  #0 for request
                       flags = 3,
                       fraglen=48,
                       Authlen=0,
                       AllocHint=24,
                       ContextID=0,
                        Cancelcount=0,
                       Opnum=15,
                       **kwargs):
        #print 'svcctsize for res', self.svcctSize
        raw = ''
        raw += HexCodeInteger(version, HexCodes=1)  # version
        raw += HexCodeInteger(minorversion, HexCodes=1)  # minor version
        raw += HexCodeInteger(packettype, HexCodes=1)  # packet type
        raw += HexCodeInteger(flags, HexCodes=1)  # packet flags
        raw += '\x10\x00\x00\x00'  # data representation  ??
        if self.subcommand == 0x26:
            raw += HexCodeInteger(self.svcctSize + 24, HexCodes=2)
        else:
            raw += HexCodeInteger(fraglen, HexCodes=2)
        raw += HexCodeInteger(Authlen, HexCodes=2)
        raw += HexCodeInteger(self.CallID, HexCodes=4)
        if self.subcommand == 0x26:
            raw += HexCodeInteger(self.svcctSize, HexCodes=4)
        else:
            raw += HexCodeInteger(AllocHint, HexCodes=4)
        raw += HexCodeInteger(ContextID, HexCodes=2)
        raw += HexCodeInteger(Cancelcount, HexCodes=1)
        raw += HexCodeInteger(0, HexCodes=1)  #pad?

        #raw += HexCodeInteger(Opnum, HexCodes=2)
        return raw


