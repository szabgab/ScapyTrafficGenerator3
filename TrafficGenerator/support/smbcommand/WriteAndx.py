import cStringIO
from Scapy_Control import *
from scapy.all import *
from SMB_COM import *
from dcerpc_layer import *

class WriteAndx(dcerpc_layer):
    def WriteAndxBindRequest(self,
                             Flow='SMB',
                             **kwargs
                             ):
        raw = self.SMBHeader(command=SMB_COM_WRITE_ANDX,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)
        if self.ActiveFile == '\\svcctl':
            fofset=57054
        else:
            if os.path.exists(self.ActiveFile):
                fofset = len(open(self.ActiveFile).read())
            else:
                fofset = 10000

        #self.ActiveFile
        raw += HexCodeInteger(14, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(fofset, HexCodes=2)  #andx offset
        #raw += HexCodeInteger(0, HexCodes=2)  # offset  ?length of file???  dede???
        raw += HexCodeInteger(self.FID, HexCodes=2)  # reserved

        raw += HexCodeInteger(0, HexCodes=4)  # offset
        raw += HexCodeInteger(0xffffffff, HexCodes=4)  # reserved
        raw += HexCodeInteger(8, HexCodes=2)  # write mode   8 is start of message pipe

        #raw += HexCodeInteger(len(DATA), HexCodes=2)
        raw += HexCodeInteger(72, HexCodes=2)  # remaining  ? size of file?  72?

        raw += HexCodeInteger(0, HexCodes=2)  # data len high

        #raw += HexCodeInteger(len(DATA), HexCodes=2)  # data len low ?72?
        raw += HexCodeInteger(72, HexCodes=2)  # data len low ?7?
        raw += HexCodeInteger(64, HexCodes=2)  # data offset ? 64?
        raw += HexCodeInteger(0, HexCodes=4)  # high offset


        ##BYTECOUNT
        dcerpc = '\xee'  #padding
        dcerpc += self.dcerpc_bind_request()
        raw += HexCodeInteger(len(dcerpc), HexCodes=2)  # byte count
        raw += dcerpc

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def WriteAndxRequest(self,
                        Flow = 'SMB',
                        **kwargs):
        raw = self.SMBHeader(command=SMB_COM_WRITE_ANDX,
                             flags=24,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(14, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(self.FID, HexCodes=2)  # reserved

        raw += HexCodeInteger(0, HexCodes=4)  # offset
        raw += HexCodeInteger(0, HexCodes=4)  # reserved
        raw += HexCodeInteger(0, HexCodes=2) # write mode
        raw += HexCodeInteger(0, HexCodes=2)  #remaining

        raw += HexCodeInteger(0, HexCodes=2)  # data len high

        if os.path.exists(self.ActiveFile):
            DATA = open(self.ActiveFile).read()
        else:
            DATA=RamdomRawData(size=10000)

        self.FileLength = len(DATA)

        raw += HexCodeInteger(len(DATA), HexCodes=2)  # data len low ?7?
        raw += HexCodeInteger(63, HexCodes=2)  # data offset ?63?
        raw += HexCodeInteger(0, HexCodes=4)  # high offset

        raw += HexCodeInteger(len(DATA), HexCodes=2)  # ByteCount
        raw += DATA

        raw = self.add_raw_to_nb(raw=raw)

        # now lets split up the raw into parts
        r = cStringIO.StringIO(raw)
        r.seek(0)
        # at this point of time raw is too large.  need to split it up into mtu (lets just make this in thousand
        bytes_remaining = len(raw)
        while bytes_remaining > 0:
            if bytes_remaining < 1000:
                load = r.read(bytes_remaining)
                bytes_remaining -= bytes_remaining
            else:
                bytes_remaining -= 1000
                load = r.read(1000)
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                           Flags='PA',
                                                           AttachLayers=load)

        r.close()



    def WriteAndxResponse(self,
                         Flow='SMB',
                         **kwargs):
        raw = self.SMBHeader(command=SMB_COM_WRITE_ANDX,
                             flags=136,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)
        if self.ActiveFile == '\\svcctl':
            lowcount = 72
        else:
            lowcount = self.FileLength

        raw += HexCodeInteger(6, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(47, HexCodes=2)  # offset
        raw += HexCodeInteger(lowcount, HexCodes=2)  # count low
        raw += HexCodeInteger(65535, HexCodes=2)  # remaining  ??65535
        raw += HexCodeInteger(0, HexCodes=2)  # high count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # byte count

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)
