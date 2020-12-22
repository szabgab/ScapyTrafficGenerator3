import cStringIO
from Scapy_Control import *
from scapy.all import *
from NBSession import *


class Write(NBSession):
    def  write_request(self,
                     **kwargs):
        print 'writing file', self.ActiveFile
        SizOfFile = len(open(self.ActiveFile).read())
        raw = ''
        raw += int_to_two_hex(49)  # structure size
        raw += HexCodeInteger(112, HexCodes=2)  # data offset
        raw += HexCodeInteger(SizOfFile, HexCodes=4)  # write length
        raw += HexCodeInteger(0, HexCodes=8)  # file offset
        raw += HexCodeInteger(self.FID, HexCodes=16)  # fileid
        raw += HexCodeInteger(0, HexCodes=4)  # channel
        raw += HexCodeInteger(0, HexCodes=4)  # remaining bytes

        #channel info blob
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(0, HexCodes=2)  # len
        raw += HexCodeInteger(0, HexCodes=4)  # write flags
        raw += open(self.ActiveFile).read()
        return raw
    def write_response(self,
                      **kwargs):
        SizOfFile = len(open(self.ActiveFile).read())
        raw = ''
        raw += int_to_two_hex(17)  # structure size
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(SizOfFile, HexCodes=4)  # write count
        raw += HexCodeInteger(0, HexCodes=8)  # write remaining
        raw += HexCodeInteger(0, HexCodes=2)  # channel offset
        raw += HexCodeInteger(0, HexCodes=2)  # channel len
        raw += '\xfd'  #no idea
        return raw

    def WriteRequest(self,
                     Flow='SMB',
                     **kwargs
                     ):


        raw = self.SMB2Header(credits=52,
                              command=9,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )

        raw += self.write_request()

        raw = self.add_raw_to_nb(raw=raw)
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


    def WriteResponse(self,
                      Flow='SMB',
                      **kwargs
                      ):
        raw = self.SMB2Header(credits=1,
                              flags=1,
                              command=9,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )

        raw += self.write_response()

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)