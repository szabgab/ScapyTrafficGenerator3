from Scapy_Control import *
from scapy.all import *
from NBSession import *

class Create_Close(NBSession):

    #SMB2_CREATE_REQUEST_LEASE
    def RqLs_Chain(self,
                   Req = True):
        raw = ''
        if Req:
            raw += HexCodeInteger(0, HexCodes=4)  # whole size offset
            raw += HexCodeInteger(16, HexCodes=2)  # offset of rqls
            raw += HexCodeInteger(4, HexCodes=4)  # len of rqls
            raw += HexCodeInteger(24, HexCodes=2)  # offset of Data
            raw += HexCodeInteger(52, HexCodes=4)  # len of Data
            raw += 'RqLs'
            raw += HexCodeInteger(0, HexCodes=4)  # reserved
            raw += RamdomRawData(size=16)# lease key
            raw += HexCodeInteger(7, HexCodes=4)  # lease state (read/write/handle)

            raw += HexCodeInteger(0, HexCodes=4)  # lease flags
            raw += HexCodeInteger(0, HexCodes=8)  # lease duration

            raw += HexCodeInteger(0, HexCodes=16)  # parent lease key
            raw += HexCodeInteger(0, HexCodes=2)  #  lease epoch
            raw += HexCodeInteger(0, HexCodes=2)  #  lease reserved
        else:
            raw += HexCodeInteger(0, HexCodes=4)  # whole size offset
            raw += HexCodeInteger(16, HexCodes=2)  # offset of rqls
            raw += HexCodeInteger(4, HexCodes=4)  # len of rqls
            raw += HexCodeInteger(24, HexCodes=2)  # offset of Data
            raw += HexCodeInteger(52, HexCodes=4)  # len of Data
            raw += 'RqLs'
            raw += HexCodeInteger(0, HexCodes=4)  # reserved
            raw += self.leasekey #RamdomRawData(size=16)  # lease key
            raw += HexCodeInteger(7, HexCodes=4)  # lease state (read/write/handle)

            raw += HexCodeInteger(0, HexCodes=4)  # lease flags
            raw += HexCodeInteger(0, HexCodes=8)  # lease duration

            raw += HexCodeInteger(0, HexCodes=16)  # parent lease key
            raw += HexCodeInteger(1, HexCodes=2)  # lease epoch
            raw += HexCodeInteger(705, HexCodes=2)  # lease reserved
            raw += HexCodeInteger(0, HexCodes=4)  # reservec
        return raw

    def create_request_file(self,
                            File,
                            IsDir=False,
                            **kwargs):

        raw = ''
        raw += int_to_two_hex(57)  # structure size
        raw += HexCodeInteger(0, HexCodes=1)  # reserved?
        raw += HexCodeInteger(255, HexCodes=1)  # batch oplock
        raw += HexCodeInteger(2, HexCodes=4)  # Imersonation
        raw += HexCodeInteger(0, HexCodes=8)  # create flags
        raw += HexCodeInteger(0, HexCodes=8)  # reserved?
        raw += HexCodeInteger(2032127, HexCodes=4)  # access mask 1f01ff
        if IsDir:
            raw += HexCodeInteger(16, HexCodes=4)  # file attributes  ordinary file/dir
        else:
            raw += HexCodeInteger(128, HexCodes=4)  # file attributes  ordinary file/dir

        raw += HexCodeInteger(7, HexCodes=4)  # access share read/write/delete
        #raw += HexCodeInteger(1, HexCodes=4)  # disposition (open it or fail))
        #raw += HexCodeInteger(2, HexCodes=4)  # disposition (if exists fail else or create it(3))
        if self.Delete:
            raw += HexCodeInteger(4, HexCodes=4)  # disposition (overwrite)
        else:

            raw += HexCodeInteger(3, HexCodes=4)  # disposition (open it or create it(3))


        if IsDir:
            raw += HexCodeInteger(1, HexCodes=4)  # create options (directory)
        else:
            if self.Delete:
                raw += HexCodeInteger(4096, HexCodes=4)  # create options (68-sequential only, non-directory)
            else:
                raw += HexCodeInteger(2097252, HexCodes=4)  # create options (68-sequential only, non-directory)



        raw += HexCodeInteger(120, HexCodes=2) # file offset
        raw += HexCodeInteger(len(File), HexCodes=2) # file name len
        NOWLEN = 120 + len(File) + 6   #6 bytes for reserved
        raw += HexCodeInteger(NOWLEN, HexCodes=4) #offset for chain elements

        CHAINELEMTS = self.RqLs_Chain()
        raw += HexCodeInteger(len(CHAINELEMTS), HexCodes=4)  # len of chain?
        raw += File
        raw += HexCodeInteger(0, HexCodes=6)  # reserved

        raw += CHAINELEMTS
        return raw

    def create_response_file(self,
                             FileExists=True,
                      **kwargs):
        SizOfFile = len(open(self.ActiveFile).read())
        raw = ''
        raw += int_to_two_hex(89)  # structure size
        raw += HexCodeInteger(255, HexCodes=1)  # batch oplock
        raw += HexCodeInteger(0, HexCodes=1)  # response flags
        if FileExists:
            raw += HexCodeInteger(1, HexCodes=4)  # 1 is the file existed and was opened
        else:
            raw += HexCodeInteger(2, HexCodes=4)  # 2 is the file did not exist but was created
        raw += HexCodeInteger(int(time.time()-1000) * 1000, HexCodes=8)  #created
        raw += HexCodeInteger(int(time.time()-50) * 1000, HexCodes=8)  #last access
        raw += HexCodeInteger(int(time.time()-100) * 1000, HexCodes=8)  #last write
        raw += HexCodeInteger(int(time.time()-100) * 1000, HexCodes=8)  #last change
        if FileExists:
            raw += HexCodeInteger(SizOfFile + 2000, HexCodes=8)  # allocate size  0 if created
            raw += HexCodeInteger(SizOfFile, HexCodes=8)  # end of file 0 if created

        else:
            raw += HexCodeInteger(0, HexCodes=8)  # allocate size  0 if created
            raw += HexCodeInteger(0, HexCodes=8)  # end of file 0 if created

        raw += HexCodeInteger(32, HexCodes=4)  # file attributes
        raw += HexCodeInteger(0, HexCodes=4)  # reserved?
        raw += HexCodeInteger(self.FID, HexCodes=16)  # fileid
        raw += HexCodeInteger(152, HexCodes=4)  # offset



        CHAINELEMTS = self.RqLs_Chain(Req=False)
        raw += HexCodeInteger(len(CHAINELEMTS), HexCodes=4)  # len of chain?
        raw += CHAINELEMTS
        return raw

    def close_request_file(self):
        raw = ''
        raw += int_to_two_hex(24)  # structure size
        raw += HexCodeInteger(0, HexCodes=2)  # close flags
        raw += HexCodeInteger(0, HexCodes=4)  # reserved
        raw += HexCodeInteger(self.FID,HexCodes=16)
        return raw

    def close_response_file(self):
        raw = ''
        raw += int_to_two_hex(60)  # structure size
        raw += HexCodeInteger(0, HexCodes=2)  # close flags
        raw += HexCodeInteger(0, HexCodes=4)  # reserved
        raw += HexCodeInteger(0, HexCodes=8)  # created
        raw += HexCodeInteger(0, HexCodes=8)  # last access
        raw += HexCodeInteger(0, HexCodes=8)  # last write
        raw += HexCodeInteger(0, HexCodes=8)  # last change
        raw += HexCodeInteger(0, HexCodes=8)  # allocation size
        raw += HexCodeInteger(0, HexCodes=8)  # end of file
        raw += HexCodeInteger(0, HexCodes=4)  # file attrib
        return raw


    def CreateFileRequest(self,
                          Flow='SMB',
                          **kwargs):

        raw = self.SMB2Header(credit=1,
                              credits=1,
                              command=5,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )
        raw += self.create_request_file(padTextafter(os.path.basename(self.ActiveFile)),
                                        leasekey=self.leasekey)
        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def CreateFileResponse(self,
                           Flow='SMB',
                           **kwargs):
        raw = self.SMB2Header(credits=1,
                              credit=1,
                              flags=1,
                              command=5,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )

        raw += self.create_response_file()

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def CloseFileRequest(self,
                         Flow='SMB',
                         **kwargs):
        raw = self.SMB2Header(credits=28,
                              command=6,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )

        raw += self.close_request_file()

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)
    def CloseFileResponse(self,
                          Flow='SMB',
                         **kwargs):
        raw = self.SMB2Header(credits=1,
                              flags=1,
                              command=6,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )

        raw += self.close_response_file()

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)