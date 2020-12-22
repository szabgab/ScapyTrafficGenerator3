from Scapy_Control import *
from scapy.all import *
from SMB_COM import *

class Delete():
    def DeleteRequest(self,
                           Flow='SMB',
                           **kwargs):
        raw = self.SMBHeader(command=SMB_COM_DELETE,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID,

                             )

        raw += HexCodeInteger(1, HexCodes=1)  # word count
        raw += HexCodeInteger(22, HexCodes=2)  # search attributes

        DATA = ''
        DATA += padTextafter(self.ActiveFile)
        DATA += HexCodeInteger(0, HexCodes=2)  # end

        raw +=HexCodeInteger(len(DATA), HexCodes=2)  # ByteCount
        raw += HexCodeInteger(4, HexCodes=1)  # buffer format
        raw += DATA

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def DeleteResponse(self,
                      Flow='SMB',
                      **kwargs):


        raw = self.SMBHeader(command=SMB_COM_DELETE,
                             flags=136,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID,

                             )

        raw += HexCodeInteger(0, HexCodes=3)
        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)