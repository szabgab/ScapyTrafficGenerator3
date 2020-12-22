
from Scapy_Control import *
from scapy.all import *
from NBSession import *

class Tree(NBSession):
    def tree_request(self,
                     tree,
                     **kwargs):
        raw = ''
        raw += int_to_two_hex(kwargs.get('size') or 9)  # structure size
        raw += HexCodeInteger(0, HexCodes=2)  # reserved?
        raw += HexCodeInteger(72, HexCodes=2)  # offset
        raw += HexCodeInteger(len(tree), HexCodes=2)  #lenth of tree
        raw += tree

        return raw

    def tree_response(self,
                      **kwargs):
        raw = ''
        raw += int_to_two_hex(kwargs.get('size') or 16)  # structure size
        raw += HexCodeInteger(1, HexCodes=1)  # pysical disk
        raw += HexCodeInteger(0, HexCodes=1)  # reserved?
        raw += HexCodeInteger(0, HexCodes=4)  # caching?
        raw += HexCodeInteger(0, HexCodes=4)  # sharing?
        raw += HexCodeInteger(0, HexCodes=4)  # access?
        raw += HexCodeInteger(2032127, HexCodes=4)  # rw,rw ext, execute, delete child, rw attrib, delete, read to owner, write dac, write owner, sync

        return raw

    def TreeRequest(self,
                    Flow='SMB',
                    **kwargs):


        raw = self.SMB2Header(credits=1,
                              credit=1,
                              command=3,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              )

        tree = self.tree or kwargs.get('tree')
        assert tree != None, 'must specify a tree connect path before moving on'
        tree = padTextafter(tree)
        raw += self.tree_request(tree)

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)


    def TreeResponse(self,
                     Flow='SMB',
                     **kwargs):
        raw = self.SMB2Header(credits=1,
                              credit=1,
                              flags=1,
                              command=3,
                              mid=self.MID,
                              pid=self.PID,
                              sessionid=self.UID,
                              tid=self.TID,
                              )
        raw += self.tree_response()

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)