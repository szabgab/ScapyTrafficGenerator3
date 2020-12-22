import time
from Scapy_Control import *
from scapy.all import *
from SMB_COM import *

class CreateAndx():
    def CreateAndxRequest(self,
                           Flow='SMB',
                          disposition=1,
                           **kwargs):
        raw = self.SMBHeader(command=SMB_COM_NT_CREATE_ANDX,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)



        raw += HexCodeInteger(24, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(len(self.ActiveFile), HexCodes=2)  # filename len
        raw += HexCodeInteger(22, HexCodes=4)  # creation flags
        raw += HexCodeInteger(0, HexCodes=4)  # root fid
        raw += HexCodeInteger(131209, HexCodes=4)  # access mask
        raw += HexCodeInteger(0, HexCodes=8)  # allocation size
        raw += HexCodeInteger(128, HexCodes=4)  # file attributes
        raw += HexCodeInteger(7, HexCodes=4)  # access ...read/write/delete
        raw += HexCodeInteger(disposition, HexCodes=4)  # disp --> 1 = open or fail, 5 is overright or create
        raw += HexCodeInteger(2112, HexCodes=4)  # create options
        raw += HexCodeInteger(2, HexCodes=4)  # impersonation
        raw += HexCodeInteger(3, HexCodes=1)  # security flags

        FP = ''  # ''\x00'
        for i in self.ActiveFile:
            FP += '\x00' + i  # .upper()
        FP += '\x00' * 3

        raw += HexCodeInteger(len(FP), HexCodes=2) #ByteCount
        raw += FP

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def CreateAndxResponse(self,
                           createAction=2,
                     Flow='SMB',
                     **kwargs):
        if self.ActiveFile == '\\svcctl':
            flength=0
        else:
            if os.path.exists(self.ActiveFile):
                DATA = open(self.ActiveFile).read()
                self.FileLength = len(DATA)
            else:
                self.FileLength=10000
                print 'File %s does not exist locally, cant write so faking a 10000 byte file'  %self.ActiveFile


        raw = self.SMBHeader(command=SMB_COM_NT_CREATE_ANDX,
                             flags=152,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID
                             )

        raw += HexCodeInteger(42, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(2, HexCodes=1)  # oplock level
        raw += HexCodeInteger(self.FID, HexCodes=2)  # offset
        raw += HexCodeInteger(createAction, HexCodes=4)  # 1 = exists and was opened, 2 is not exist but created
        raw += HexCodeInteger(int(time.time() * 1000), HexCodes=8)  #created
        raw += HexCodeInteger(int(time.time() * 1000), HexCodes=8)  #last access
        raw += HexCodeInteger(int(time.time() * 1000), HexCodes=8)  #last write
        raw += HexCodeInteger(int(time.time() * 1000), HexCodes=8)  #change

        raw += HexCodeInteger(2080, HexCodes=4)  # file attributes
        raw += HexCodeInteger(self.FileLength +4096, HexCodes=8)  # allocation size
        raw += HexCodeInteger(self.FileLength , HexCodes=8)  # end of file
        raw += HexCodeInteger(0, HexCodes=2)  # file/dir type  (o)


        raw += HexCodeInteger(7, HexCodes=2)  # IPC STATE
        raw += HexCodeInteger(0, HexCodes=1)  # is dir (o is not)
        raw += HexCodeInteger(0, HexCodes=16)  # volume guid
        raw += HexCodeInteger(0, HexCodes=8)  # server unique file id
        raw += HexCodeInteger(2032127, HexCodes=4)  # access mask max rights

        raw += HexCodeInteger(0, HexCodes=4)  # access mask guest
        raw += HexCodeInteger(0, HexCodes=2)  # byte count


        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)