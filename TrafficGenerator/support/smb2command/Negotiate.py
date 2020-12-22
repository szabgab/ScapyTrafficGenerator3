
from Scapy_Control import *
from scapy.all import *
from NBSession import *


class Negotiate(NBSession):
    def SMB2_Negotiate_Request(self,
                               Dialects=['\x02\x02',
                                         '\x02\x10',
                                         '\x02\x22',
                                         '\x02\x24',
                                         '\x03\x00'],
                               **kwargs):
        raw = ''
        raw += int_to_two_hex(kwargs.get('size') or 36)  # structure size
        raw += HexCodeInteger(len(Dialects), HexCodes=2)
        raw += HexCodeInteger(kwargs.get('smode') or 0, HexCodes=1)
        raw += '\x00\x00\x00'  # dont know what this is , just reserved filler
        raw += int_to_four_hex(kwargs.get('capabilities') or 127)
        raw += kwargs.get('ClientGUI') or RamdomRawData(size=16)
        raw += HexCodeInteger(kwargs.get('boottime') or 0, HexCodes=8)
        for Dialect in Dialects:
            raw += Dialect
        return raw

    def SMB2_Negotiate_Response(self,
                                ChosenDialect = '\x02\x02',
                                **kwargs):
        raw = ''
        raw += int_to_two_hex(65)  # structure size
        raw += HexCodeInteger(1, HexCodes=1)  # '\x01'  # security mode
        raw += '\x00'  # don't know
        raw += ChosenDialect  # dialect
        raw += '\x00\x00'  # don't know
        raw += kwargs.get('guid') or RamdomRawData(size=16)  # Server GUID
        raw += int_to_four_hex(1)  # capabilities
        raw += int_to_four_hex(65536)  # Max Transaction Size
        raw += int_to_four_hex(65536)  # Max Read Size
        raw += int_to_four_hex(65536)  # Max write Size
        raw += HexCodeInteger(int(time.time() * 1000), HexCodes=8)  # system time
        raw += HexCodeInteger(int(time.time()-1000) * 1000, HexCodes=8)  # boot time

        ### Security blob
        raw += int_to_two_hex(128)  # offset
        raw += int_to_two_hex(30)  # legth of GSSAPI

        raw += '\x20\x4c\x4d\x20'  # i have no idea what this is but it is not included in hex length

        ###GSS-API (Generic Security Service Application Protocol Interface  (the value of this adds up to legth of GSSAPI
        raw += '\x60\x1c\x06\x06'  # i have no idea what this is  +4=4 bytes
        raw += '\x2b\x06\x01\x05\x05\x02'  # oid for simple protected negotiation  +6=10bytes
        raw += '\xa0\x12'  # simp protected neg start ? maybe' +2=12 bytes
        raw += '\x30\x10\xa0\x0e\x30\x0c'  # negTokenInit +6 = 18 bytes
        raw += '\x06\x0a'  # machtype 1 item +2 = 20 bytes
        raw += '\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'  # oid for NTLM Security Support Provider  +10=30bytes

        return raw

    # this negotiate request is the same as in smb1
    def NegotiateSMB2Request(self,
                             Flow='SMB',
                             **kwargs):
        raw = self.SMB2Header(command=0)

        raw += self.SMB2_Negotiate_Request(smode=1)

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=load)

    def NegotiateSMB2Response(self,
                              selectedIndex=4,
                              Flow='SMB',
                              **kwargs):
        raw = self.SMB2Header(credits=1,
                              flags=1,
                              command=0,
                              mid=self.MID,
                              pid=self.PID
                              )

        raw += self.SMB2_Negotiate_Response(guid=self.GUID)

        raw = self.add_raw_to_nb(raw=raw)
        load = Raw(load=raw)
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=load)