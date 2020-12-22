
from Scapy_Control import *
from scapy.all import *
from NBSession import *
import cStringIO


class Read(NBSession):
    def read_request(self,
                     **kwargs):
        print 'reading file', self.ActiveFile
        SizOfFile = len(open(self.ActiveFile).read())
        raw = ''
        raw += int_to_two_hex(49)  # structure size
        raw += HexCodeInteger(80, HexCodes=2)  # no idea
        raw += HexCodeInteger(SizOfFile, HexCodes=4)  # read length
        raw += HexCodeInteger(0, HexCodes=8)  # file offset
        raw += HexCodeInteger(self.FID, HexCodes=16)  # fileid
        raw += HexCodeInteger(1, HexCodes=4)  # min count?
        raw += HexCodeInteger(0, HexCodes=4)  # channel
        raw += HexCodeInteger(0, HexCodes=4)  # remaining bytes

        #channel info blob
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(0, HexCodes=2)  # len
        raw += HexCodeInteger(0, HexCodes=3)  # ?
        return raw
    def read_response(self,
                      **kwargs):
        SizOfFile = len(open(self.ActiveFile).read())
        raw = ''
        raw += int_to_two_hex(17)  # structure size
        raw += HexCodeInteger(80, HexCodes=2)  # data offset
        raw += HexCodeInteger(SizOfFile, HexCodes=4)  # read length
        raw += HexCodeInteger(0, HexCodes=4)  # read remaining
        raw += HexCodeInteger(0, HexCodes=4)  # read reserved

        raw += open(self.ActiveFile).read()
        return raw




    def ReadRequest(self,
                    Flow='SMB',
                    **kwargs):
        raw = self.SMB2Header(credits=28,
                              command=8,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )
        raw += self.read_request()

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def ReadResponse(self,
                     Flow='SMB',
                     **kwargs):


        raw = self.SMB2Header(credits=1,
                              flags=1,
                              command=8,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )
        raw += self.read_response()

        raw = self.add_raw_to_nb(raw=raw)
        r = cStringIO.StringIO(raw)
        r.seek(0)
        #at this point of time raw is too large.  need to split it up into mtu (lets just make this in thousand
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

