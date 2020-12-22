import cStringIO
from Scapy_Control import *
from scapy.all import *
from SMB_COM import *

class ReadAndx():
    def ReadAndxRequest(self,
                        Flow = 'SMB',
                        **kwargs):
        raw = self.SMBHeader(command=SMB_COM_READ_ANDX,
                             flags=24,
                             flags2=59399,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(12, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(self.FID, HexCodes=2)  # FID
        raw += HexCodeInteger(kwargs.get('offset') or 0, HexCodes=4)  # offset
        raw += HexCodeInteger(len(open(self.ActiveFile).read()), HexCodes=2)  # max low count
        raw += HexCodeInteger(0, HexCodes=2)  # mincount
        raw += HexCodeInteger(0, HexCodes=4)  # maxhigh
        raw += HexCodeInteger(0, HexCodes=2)  # remaining
        raw += HexCodeInteger(0, HexCodes=4)  # highoffset
        raw += HexCodeInteger(0, HexCodes=2)  # bytecound

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def ReadAndxResponse(self,
                         Flow='SMB',
                         **kwargs):
        raw = self.SMBHeader(command=SMB_COM_READ_ANDX,
                             flags=152,
                             flags2=59399,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)
        fsize = len(open(self.ActiveFile).read())
        raw += HexCodeInteger(12, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(0, HexCodes=2)  # remaining    ********************************************************65535
        raw += HexCodeInteger(0, HexCodes=2)  # data compaction mode
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(fsize, HexCodes=2)  # data len low
        raw += HexCodeInteger(60, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=4)  # data len high
        raw += HexCodeInteger(0, HexCodes=6)  # reserved
        raw += HexCodeInteger(fsize+1, HexCodes=2)  # ByteCount
        raw += HexCodeInteger(0, HexCodes=1)  # padding

        raw += open(self.ActiveFile).read()

        raw = self.add_raw_to_nb(raw=raw)

        #now lets split up the raw into parts
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
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                           Flags='PA',
                                                           AttachLayers=load)

        r.close()