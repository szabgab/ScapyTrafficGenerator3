from scapy.all import *

from Scapy_Control import *
from SMB_COM import *
from dcerpc_layer import *
from msft_service_control import *


class Trans(dcerpc_layer, msft_service_control):
    def open_scManager_request(self,
                          Flow='SMB'):

        # get svcctl layer
        svcctl = self.svcctl_open_SC_Manager_request(machinename=self.dst)

        # get dcrpc layer
        dcerpc = self.dcerpc_request()

        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(16, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(len(dcerpc)+len(svcctl), HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(1024, HexCodes=2)  # max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(84, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(80, HexCodes=2)  # data count
        raw += HexCodeInteger(84, HexCodes=2)  # data offset
        raw += HexCodeInteger(2, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved


        #this i Open ServcieW request
        raw += HexCodeInteger(0x26, HexCodes=2)  #subcommand for open service
        raw += HexCodeInteger(self.FID, HexCodes=2)
        command = '\x00'
        command += padTextafter(self.Pipename) + '\x00\x00'
        command += HexCodeInteger(0, HexCodes=2)  # padding


        command += dcerpc
        command += svcctl
        raw += HexCodeInteger(len(command), HexCodes=2)  # BYTE COUNT
        raw += command

        raw = self.add_raw_to_nb(raw=raw)

        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def open_scManager_response(self,
                                Flow='SMB'):

        svcctl = self.svcctl_open_response()

        dcrpc = '\x00'  # padding
        dcrpc += self.dcerpc_response()
        #self.dcerpclen+=1  #??
        dcrpc += svcctl

        #print 'open repsonse size', self.dcerpclen + self.svcctSize


        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=152,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(10, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(56, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(56, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=2)  # data displacement
        raw += HexCodeInteger(0, HexCodes=1)  # setup
        raw += HexCodeInteger(0, HexCodes=1)  # reserved


        #dcrpc += self.svcctl_response()
        raw += HexCodeInteger(len(dcrpc), HexCodes=2)  # bytecount
        raw += dcrpc
        raw = self.add_raw_to_nb(raw=raw)
        # attach dcrpc layer
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def CreateServiceW_request(self,
                               Flow = 'SMB'):
        # svcctl layer
        svcctl = self.svcct_createService_request()

        # dcrpc layer
        dcerpc = self.dcerpc_request()

        #print 'create data size', self.dcerpclen+self.svcctSize

        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)


        raw += HexCodeInteger(16, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen+self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(1024, HexCodes=2)  # max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(84, HexCodes=2)  # parameter offset
        # raw += HexCodeInteger(76, HexCodes=2)  # data count
        raw += HexCodeInteger(self.dcerpclen+self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(84, HexCodes=2)  # data offset
        raw += HexCodeInteger(2, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        # this i createw request
        raw += HexCodeInteger(0x26, HexCodes=2)  # subcommand for open service
        raw += HexCodeInteger(self.FID, HexCodes=2)
        command = '\x00'  ## pad ??
        command += padTextafter(self.Pipename) + '\x00\x00'
        command += HexCodeInteger(0, HexCodes=2)  # padding




        command += dcerpc
        command += svcctl
        raw += HexCodeInteger(len(command), HexCodes=2)  # BYTE COUNT
        raw += command

        raw = self.add_raw_to_nb(raw=raw)

        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def CreateServiceW_response(self,
                               Flow='SMB'):


        # svcctl layer
        svcctl = self.svcctl_create_response()

        # dcrpc layer
        dcrpc = '\x00'  # padding
        dcrpc += self.dcerpc_response()
        dcrpc += svcctl

        #print 'create resp data size', self.dcerpclen + self.svcctSize
        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=152,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(10, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(56, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(56, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=2)  # data displacement
        raw += HexCodeInteger(0, HexCodes=1)  # setup
        raw += HexCodeInteger(0, HexCodes=1)  # reserved


        raw += HexCodeInteger(len(dcrpc), HexCodes=2)  # bytecount
        raw += dcrpc
        raw = self.add_raw_to_nb(raw=raw)
        # attach dcrpc layer
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def closeServcieHandle_Response(self,
                                    Flow='SMB',
                                    ):

        # svcctl layer
        svcctl = self.svcct_closehandle_response()

        # dcrpc layer
        dcrpc = '\x00'  # padding
        dcrpc += self.dcerpc_response()
        dcrpc += svcctl

        #print 'close handle response data size', self.dcerpclen + self.svcctSize
        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=152,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(10, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(56, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(56, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=2)  # data displacement
        raw += HexCodeInteger(0, HexCodes=1)  # setup
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        raw += HexCodeInteger(len(dcrpc), HexCodes=2)  # bytecount
        raw += dcrpc
        raw = self.add_raw_to_nb(raw=raw)
        # attach dcrpc layer
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def closeServcieHandle_Request(self,
                                   Flow='SMB',
                                   handle=True,
                                   ):

        # svcctl layer
        svcctl = self.svcct_closehandle_request(handle=handle)

        # dcrpc layer
        dcerpc = self.dcerpc_request()

        #print 'close handle size', self.dcerpclen + self.svcctSize



        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(16, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(1024, HexCodes=2)  # max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(84, HexCodes=2)  # parameter offset
        # raw += HexCodeInteger(76, HexCodes=2)  # data count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(84, HexCodes=2)  # data offset
        raw += HexCodeInteger(2, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved



        # this i close service handle request
        raw += HexCodeInteger(0x26, HexCodes=2)  # subcommand for open service
        raw += HexCodeInteger(self.FID, HexCodes=2)
        command = '\x00'  ## pad ??
        command += padTextafter(self.Pipename) + '\x00\x00'
        command += HexCodeInteger(0, HexCodes=2)  # padding

        command += dcerpc
        command += svcctl
        raw += HexCodeInteger(len(command), HexCodes=2)  # BYTE COUNT
        raw += command

        raw = self.add_raw_to_nb(raw=raw)

        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def openServicew_Request(self,
                             Flow='SMB',
                             ):


        # svcctl layer
        svcctl = self.svcct_open_request()

        # dcrpc layer
        dcerpc = self.dcerpc_request()

        #print 'open service size', self.dcerpclen + self.svcctSize

        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(16, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(1024, HexCodes=2)  # max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(84, HexCodes=2)  # parameter offset
        # raw += HexCodeInteger(76, HexCodes=2)  # data count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(84, HexCodes=2)  # data offset
        raw += HexCodeInteger(2, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        # this i close service handle request
        raw += HexCodeInteger(0x26, HexCodes=2)  # subcommand for open service
        raw += HexCodeInteger(self.FID, HexCodes=2)
        command = '\x00'  ## pad ??
        command += padTextafter(self.Pipename) + '\x00\x00'
        command += HexCodeInteger(0, HexCodes=2)  # padding

        command += dcerpc
        command += svcctl
        raw += HexCodeInteger(len(command), HexCodes=2)  # BYTE COUNT
        raw += command

        raw = self.add_raw_to_nb(raw=raw)

        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def startServicew_Request(self,
                             Flow='SMB'
                              ):


        # svcctl layer
        svcctl = self.svcct_start_request()

        # dcrpc layer
        dcerpc = self.dcerpc_request()

        #print 'start service size', self.dcerpclen + self.svcctSize

        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(16, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(1024, HexCodes=2)  # max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(84, HexCodes=2)  # parameter offset
        # raw += HexCodeInteger(76, HexCodes=2)  # data count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(84, HexCodes=2)  # data offset
        raw += HexCodeInteger(2, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        # this i close service handle request
        raw += HexCodeInteger(0x26, HexCodes=2)  # subcommand for open service
        raw += HexCodeInteger(self.FID, HexCodes=2)
        command = '\x00'  ## pad ??
        command += padTextafter(self.Pipename) + '\x00\x00'
        command += HexCodeInteger(0, HexCodes=2)  # padding

        command += dcerpc
        command += svcctl
        raw += HexCodeInteger(len(command), HexCodes=2)  # BYTE COUNT
        raw += command

        raw = self.add_raw_to_nb(raw=raw)

        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def startServicew_Response(self,
                              Flow='SMB',
                               ):
        # svcctl layer
        svcctl = HexCodeInteger(0, HexCodes=4)  #error (success)
        self.svcctSize = 4

        # dcrpc layer
        dcrpc = '\x00'  # padding
        dcrpc += self.dcerpc_response()
        dcrpc += svcctl

        #print 'close handle response data size', self.dcerpclen + self.svcctSize
        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=152,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(10, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(56, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(56, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=2)  # data displacement
        raw += HexCodeInteger(0, HexCodes=1)  # setup
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        raw += HexCodeInteger(len(dcrpc), HexCodes=2)  # bytecount
        raw += dcrpc
        raw = self.add_raw_to_nb(raw=raw)
        # attach dcrpc layer
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def queryStatus_request(self,
                              Flow='SMB',
                            ):


        # svcctl layer
        svcctl = self.svcct_queryStatus_request()

        # dcrpc layer
        dcerpc = self.dcerpc_request()

        #print 'start service size', self.dcerpclen + self.svcctSize

        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=24,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(16, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(1024, HexCodes=2)  # max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(84, HexCodes=2)  # parameter offset
        # raw += HexCodeInteger(76, HexCodes=2)  # data count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(84, HexCodes=2)  # data offset
        raw += HexCodeInteger(2, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        # this i close service handle request
        raw += HexCodeInteger(0x26, HexCodes=2)  # subcommand for open service
        raw += HexCodeInteger(self.FID, HexCodes=2)
        command = '\x00'  ## pad ??
        command += padTextafter(self.Pipename) + '\x00\x00'
        command += HexCodeInteger(0, HexCodes=2)  # padding

        command += dcerpc
        command += svcctl
        raw += HexCodeInteger(len(command), HexCodes=2)  # BYTE COUNT
        raw += command

        raw = self.add_raw_to_nb(raw=raw)

        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def queryStatus_Response(self,
                               Flow='SMB',
                             ):


        # svcctl layer
        svcctl = self.svcct_queryStatus_response()

        # dcrpc layer
        dcrpc = '\x00'  # padding
        dcrpc += self.dcerpc_response()
        dcrpc += svcctl

        #print 'close handle response data size', self.dcerpclen + self.svcctSize
        raw = self.SMBHeader(command=SMB_COM_TRANSACTION,
                             flags=152,
                             flags2=51207,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(10, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # parameter count
        raw += HexCodeInteger(56, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(self.dcerpclen + self.svcctSize, HexCodes=2)  # data count
        raw += HexCodeInteger(56, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=2)  # data displacement
        raw += HexCodeInteger(0, HexCodes=1)  # setup
        raw += HexCodeInteger(0, HexCodes=1)  # reserved

        raw += HexCodeInteger(len(dcrpc), HexCodes=2)  # bytecount
        raw += dcrpc
        raw = self.add_raw_to_nb(raw=raw)
        # attach dcrpc layer
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def ServiceFlow(self,
                      Flow='SMB',
                      **kwargs):
        #print 'dst', self.dst
        #open manager
        if self.AlterMID: self.MID += 1
        self.open_scManager_request(Flow=Flow)
        self.open_scManager_response(Flow=Flow)


        #create service (connect/create/etc)
        if self.AlterMID: self.MID += 1
        self.CallID += 1
        self.Opnum = 12
        self.CreateServiceW_request(Flow=Flow,
                                    **kwargs)
        self.CreateServiceW_response(Flow=Flow,
                                     **kwargs)

        # close service handles
        if self.AlterMID: self.MID += 1
        self.CallID += 1
        self.Opnum = 0
        self.closeServcieHandle_Request(Flow=Flow,
                                        handle=False,
                                    **kwargs)
        self.closeServcieHandle_Response(Flow=Flow,
                                         **kwargs)

        if self.AlterMID: self.MID += 1
        self.CallID += 1
        self.Opnum = 16
        self.openServicew_Request(Flow=Flow,
                                         **kwargs)
        self.open_scManager_response(Flow=Flow,
                                     **kwargs)

        if self.AlterMID: self.MID += 1
        self.CallID += 1
        self.Opnum = 19

        self.startServicew_Request(Flow=Flow,
                                     **kwargs)
        self.startServicew_Response(Flow=Flow,
                                   **kwargs)

        if self.AlterMID: self.MID += 1
        self.CallID += 1
        self.Opnum = 6

        self.queryStatus_request(Flow=Flow,
                                     **kwargs)

        self.queryStatus_Response(Flow=Flow,
                                     **kwargs)


        print 'do bad stuff after query'

        # close service handles
        if self.AlterMID: self.MID += 1
        self.CallID += 1
        self.Opnum = 0
        self.closeServcieHandle_Request(Flow=Flow,
                                        handle=False,
                                        **kwargs)
        self.closeServcieHandle_Response(Flow=Flow,
                                         **kwargs)

        self.closeServcieHandle_Request(Flow=Flow,
                                        **kwargs)

        self.closeServcieHandle_Response(Flow=Flow,
                                         **kwargs)


class Trans2():
    def Trans2Request(self,
                      Flow = 'SMB',
                        **kwargs):
        raw = self.SMBHeader(command=SMB_COM_TRANSACTION2,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(15, HexCodes=1)  # word count
        raw += HexCodeInteger(2, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(0, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # max param count
        raw += HexCodeInteger(65535, HexCodes=2)  #max data count
        raw += HexCodeInteger(0, HexCodes=1)  # max setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=4)  # return immediately
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(2, HexCodes=2)  # parameter count
        raw += HexCodeInteger(68, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # data count
        raw += HexCodeInteger(72, HexCodes=2)  # data offset
        raw += HexCodeInteger(1, HexCodes=1)  # setup count
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(self.subcommand, HexCodes=2)  # SUBCOMMAND   ************* 7 query_file_info

        raw += HexCodeInteger(7, HexCodes=2)  # BYTE COUNT
        raw += HexCodeInteger(0, HexCodes=3)  # padding
        raw += HexCodeInteger(self.FID, HexCodes=2)  # padding
        raw += HexCodeInteger(1008, HexCodes=2)  # level of interest (1008 is unknown)


        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def Trans2Response(self,
                         Flow='SMB',
                         **kwargs):
        raw = self.SMBHeader(command=SMB_COM_TRANSACTION2,
                             flags=136,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)


        raw += HexCodeInteger(10, HexCodes=1)  # word count
        raw += HexCodeInteger(2, HexCodes=2)  # total parameter count
        raw += HexCodeInteger(4, HexCodes=2)  # total data count
        raw += HexCodeInteger(0, HexCodes=2)  # reserved
        raw += HexCodeInteger(2, HexCodes=2)  # parameter count
        raw += HexCodeInteger(56, HexCodes=2)  # parameter offset
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(4, HexCodes=2)  # data count
        raw += HexCodeInteger(60, HexCodes=2)  # data offset
        raw += HexCodeInteger(0, HexCodes=2)  # data displacement
        raw += HexCodeInteger(0, HexCodes=2)  # parameter displacement
        raw += HexCodeInteger(0, HexCodes=1)  # setup
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(9, HexCodes=1)  # bytecount
        raw += HexCodeInteger(0, HexCodes=1)  # padding
        raw += HexCodeInteger(0, HexCodes=2)  # file info params error offet =0
        raw += HexCodeInteger(1, HexCodes=2)  # padding
        raw += HexCodeInteger(129, HexCodes=4)  # query file info (129 level unknown)



        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)


class NTTrans():
    def NTTransRequest(self,
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

    def NTTransResponse(self,
                         Flow='SMB',
                         **kwargs):
        raw = self.SMBHeader(command=SMB_COM_CLOSE,
                             flags=136,
                             flags2=51201,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        fsize = len(open(self.ActiveFile).read())
        raw += HexCodeInteger(0, HexCodes=1)  # word count
        raw += HexCodeInteger(0, HexCodes=2)  # bytecount
        raw += HexCodeInteger(0, HexCodes=2)  # ??

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)

