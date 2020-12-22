from scapy.all import *

from Scapy_Control import *
from SMB_COM import *


class Close():
    def CloseRequest(self,
                        Flow = 'SMB',
                        **kwargs):
        raw = self.SMBHeader(command=SMB_COM_CLOSE,
                             flags=8,
                             flags2=51201,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(33, HexCodes=1)  # word count
        raw += HexCodeInteger(self.FID, HexCodes=2)  # FID
        raw += HexCodeInteger(16777215, HexCodes=4)  #unspecified last write
        raw += HexCodeInteger(0, HexCodes=2)  # bytecount

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def CloseResponse(self,
                         Flow='SMB',
                         **kwargs):
        raw = self.SMBHeader(command=SMB_COM_CLOSE,
                             flags=156,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(0, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # bytecount

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)
