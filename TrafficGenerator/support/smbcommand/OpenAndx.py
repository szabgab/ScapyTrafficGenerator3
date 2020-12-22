import time
from Scapy_Control import *
from scapy.all import *
from SMB_COM import *

class OpenAndx():
    def OpenAndxRequest(self,
                           Flow='SMB',
                           **kwargs):
        raw = self.SMBHeader(command=SMB_COM_OPEN_ANDX,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             )

        FP = ''  # ''\x00'
        for i in self.ActiveFile:
            FP += '\x00' + i  # .upper()
        FP += '\x00' * 3

        raw += HexCodeInteger(12, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(26635, HexCodes=2)  # flags
        raw += HexCodeInteger(66, HexCodes=2)  # desired access
        raw += HexCodeInteger(6, HexCodes=2)  # search attrib
        raw += HexCodeInteger(0, HexCodes=2)  # file attrib
        raw += HexCodeInteger(0, HexCodes=4)  #created date

        raw += HexCodeInteger(17, HexCodes=2)  # open function (1100 is create if does not exist and open if exist

        raw += HexCodeInteger(0, HexCodes=4)  # allocate size
        raw += HexCodeInteger(0, HexCodes=4)  # timeoute 0 is return imediately
        raw += HexCodeInteger(0, HexCodes=4)  # Reserved


        raw += int_to_two_hex(len(FP))  # self.int_to_two_hex(FILESIZE) #\x73\x73 byte Count
        raw += FP

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                    AttachLayers=load)

    def OpenAndxResponse(self,
                     Flow='SMB',
                     **kwargs):

        FP = ''  # ''\x00'
        for i in self.ActiveFile:
            FP += '\x00' + i  # .upper()
        FP += '\x00' * 3

        raw = self.SMBHeader(command=SMB_COM_OPEN_ANDX,
                             flags=136,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             )

        raw += HexCodeInteger(12, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(self.FID, HexCodes=2)  # FID
        raw += HexCodeInteger(0, HexCodes=2)  # file attrib
        raw += HexCodeInteger(0, HexCodes=4)  # last write date
        raw += HexCodeInteger(len(open(self.ActiveFile).read()), HexCodes=4)  # file size
        raw += HexCodeInteger(0, HexCodes=2)  # granted access
        raw += HexCodeInteger(0, HexCodes=2)   # type file or dir (0)
        raw += HexCodeInteger(0, HexCodes=2)  # IPC state
        raw += HexCodeInteger(2, HexCodes=2)  # open action
        raw += HexCodeInteger(0, HexCodes=4)   # server fid
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # Byte Count


        # raw += HexCodeInteger(len(FP), HexCodes=2)  # Byte Count
        # raw += FP

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)
