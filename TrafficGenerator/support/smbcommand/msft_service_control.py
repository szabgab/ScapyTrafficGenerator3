from Scapy_Control import *
from scapy.all import *
class msft_service_control():
    def svcctl_open_SC_Manager_request(self,
                                        Flow='SMB',
                           RefId='\x00\x00\x02\x00',
                           offset=0,
                           machinename=None,
                           accessmask=0x000f003f,
                           **kwargs
                           ):

        if machinename == None:
            machinename = GenerateRandomIp()

        machinename = padTextafter(machinename)
        machinename+= HexCodeInteger(0, HexCodes=30-len(machinename))  #ip is fixed to 30
        raw = ''

        raw += RefId
        #raw += HexCodeInteger(mlen, HexCodes=4)
        raw += HexCodeInteger(15, HexCodes=4)
        raw += HexCodeInteger(offset, HexCodes=4)
        raw += HexCodeInteger(15, HexCodes=4)
        #raw += HexCodeInteger(mlen, HexCodes=4)
        raw += machinename
        raw += HexCodeInteger(0, HexCodes=2)  #?
        raw += HexCodeInteger(0, HexCodes=4) # 0 (null pointer) database
        raw += HexCodeInteger(accessmask, HexCodes=4)
        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw

    def svcctl_open_response(self,
                        returncode=0,  #o is success# s
                       **kwargs):
        raw = ''
        raw += self.context_handle
        raw += HexCodeInteger(returncode, HexCodes=4)  #pad4
        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw

    def svcctl_create_response(self,
                             returncode=0,  # o is success# s
                               tag=0,
                             **kwargs):


        raw = ''
        raw += HexCodeInteger(tag, HexCodes=4)  # tag
        raw += self.context_handle
        raw += HexCodeInteger(returncode, HexCodes=4)  # pad4
        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw

    def svcct_open_request(self,
                                   RefId='\x00\x00\x02\x00',
                                   offset=0,
                                   mxcount=9,
                                   actualcount=9,
                                   accessmask=0x000001ff,
                                   **kwargs
                                   ):

        # service name
        raw = ''
        raw += self.context_handle

        raw += HexCodeInteger(mxcount, HexCodes=4)
        raw += HexCodeInteger(offset, HexCodes=4)
        raw += HexCodeInteger(actualcount, HexCodes=4)

        raw += padTextafter(self.Service)
        raw += '\x00\x00'  # end of service

        raw += '\x00\x00'  # not sure
        raw += HexCodeInteger(accessmask, HexCodes=4)

        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw



    def svcct_createService_request(self,
                                   RefId='\x00\x00\x02\x00',
                                    mxcount=9,
                                    actualcount = 9,
                                   offset=0,
                                   accessmask=0x0001ff,
                                    ServiceType=16,
                                    StartType=3, #on demand

                                   **kwargs
                                   ):
        binarypath = "%" + "SystemRoot" "%" + "\\%s.exe" % self.Service
        self.svcctSize = 110
        self.svcctSize += len(self.Service) * 4 #for display and servcie name
        self.svcctSize += len(binarypath) * 2  #


        raw = ''
        raw += self.context_handle



        #service name
        raw += HexCodeInteger(mxcount, HexCodes=4)
        raw += HexCodeInteger(offset, HexCodes=4)
        raw += HexCodeInteger(actualcount, HexCodes=4)

        raw += padTextafter(self.Service)
        raw += '\x00\x00'  #end of service

        raw += HexCodeInteger(114, HexCodes=2)  #??
        raw += RefId

        #display name
        raw += HexCodeInteger(mxcount, HexCodes=4)
        raw += HexCodeInteger(offset, HexCodes=4)
        raw += HexCodeInteger(actualcount, HexCodes=4)

        raw += padTextafter(self.Service)
        raw += '\x00\x00'  # end of service

        raw += HexCodeInteger(101, HexCodes=2)  #??

        raw += HexCodeInteger(accessmask, HexCodes=4)
        raw += HexCodeInteger(ServiceType, HexCodes=4)
        raw += HexCodeInteger(StartType, HexCodes=4)
        raw += HexCodeInteger(0, HexCodes=4)  ## o error ignor

        # binary path name
        raw += HexCodeInteger(len(binarypath)+1, HexCodes=4)
        raw += HexCodeInteger(offset, HexCodes=4)
        raw += HexCodeInteger(len(binarypath)+1, HexCodes=4)
        raw += padTextafter(binarypath)
        raw += '\x00\x00'  # end of bynary path

        raw += HexCodeInteger(0, HexCodes=4)  ## o null pointer load order group
        raw += HexCodeInteger(0, HexCodes=4)  ## o tag id
        raw += HexCodeInteger(0, HexCodes=4)  ## o dependencies
        raw += HexCodeInteger(0, HexCodes=4)  ## o depend size
        raw += HexCodeInteger(0, HexCodes=4)  ## o null pointer service start name
        raw += HexCodeInteger(0, HexCodes=4)  ## o null pointer password
        raw += HexCodeInteger(0, HexCodes=4)  ## o password size
        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw

    def svcct_start_request(self,
                            **kwargs
                            ):


        raw = ''
        raw += self.context_handle
        HexCodeInteger(0, HexCodes=6)
        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw



    def svcct_closehandle_request(self,
                                  handle=True,
                                    **kwargs
                                    ):
        raw = ''
        if handle :
            raw += self.context_handle
        else:
            raw += HexCodeInteger(0, HexCodes=4) + RamdomRawData(size=16)
        self.Opnum=0

        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw

    def svcct_closehandle_response(self,
                                  **kwargs
                                  ):


        raw = ''
        raw += HexCodeInteger(0, HexCodes=20)
        raw += HexCodeInteger(0, HexCodes=4)

        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw

    def svcct_queryStatus_request(self,
                                  handle=True,
                                  **kwargs
                                  ):

        raw = ''
        if handle:
            raw += self.context_handle
        else:
            raw += HexCodeInteger(0, HexCodes=4) + RamdomRawData(size=16)
        self.Opnum = 6

        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw


    def svcct_queryStatus_response(self,
                                   **kwargs
                                   ):
        raw = ''
        raw += HexCodeInteger(16, HexCodes=4) #??
        raw += HexCodeInteger(3, HexCodes=4) #??
        raw += HexCodeInteger(1, HexCodes=4)  # ??
        raw += HexCodeInteger(0, HexCodes=4)  # ??
        raw += HexCodeInteger(0, HexCodes=4)  # ??
        raw += HexCodeInteger(2, HexCodes=4)  # ??
        raw += HexCodeInteger(0, HexCodes=4)  # ??
        raw += HexCodeInteger(0, HexCodes=4)  # ??
        self.svcctSize = len(raw)
        #print 'svcctSize', self.svcctSize
        return raw