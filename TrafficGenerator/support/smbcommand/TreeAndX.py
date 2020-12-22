from Scapy_Control import *
from scapy.all import *
from SMB_COM import *

class TreeAndX():
    def TreeConnectRequest(self,
                           Flow='SMB',
                           **kwargs):
        raw = self.SMBHeader(command=SMB_COM_TREE_CONNECT_ANDX,
                             flags=8,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             )

        raw += HexCodeInteger(4, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(0, HexCodes=2)  # offset
        raw += HexCodeInteger(0, HexCodes=2)  # flags
        raw += HexCodeInteger(0, HexCodes=2)  # pw len

        DATA = ''
        #path
        DATA +=  HexCodeInteger(0, HexCodes=1) #start
        DATA += padTextafter(self.tree)  #path
        DATA += HexCodeInteger(0, HexCodes=2)  # fin

        #service
        DATA += self.service #service
        DATA += HexCodeInteger(0, HexCodes=1)  # fin

        #print 'tree data len', len(DATA)
        raw += HexCodeInteger(len(DATA), HexCodes=2)  # pw len
        raw += DATA

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def TreeConnectResponse(self,
                            Flow='SMB',
                            **kwargs):
        raw = self.SMBHeader(command=SMB_COM_TREE_CONNECT_ANDX,
                             flags=136,
                             flags2=51203,
                             mid=self.MID,
                             pid=self.PID,
                             uid=self.UID,
                             tid=self.TID)

        raw += HexCodeInteger(3, HexCodes=1)  # word count
        raw += HexCodeInteger(255, HexCodes=1)  # andX (255 no further commands
        raw += HexCodeInteger(0, HexCodes=1)  # reserved
        raw += HexCodeInteger(54, HexCodes=2)  # offset ?
        raw += HexCodeInteger(1, HexCodes=2)  # optional support  (1 search bits)

        #self.service = 'A'
        DATA = ''

        #service
        DATA += '%s:' %self.service
        DATA += HexCodeInteger(0, HexCodes=1)  # end service
        #file system
        DATA += padTextafter('NTFS')
        DATA += HexCodeInteger(0, HexCodes=2)  #end
        raw += HexCodeInteger(len(DATA), HexCodes=2)  # Byte Count
        raw += DATA

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)