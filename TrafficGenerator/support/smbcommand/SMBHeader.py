from Scapy_Control import *

class SMBHeader(object):
    def SMBHeader(self,
                   **kwargs):
        ### SMB2 head
        raw = '\xffSMB'  # smb2 component
        raw += HexCodeInteger(kwargs.get('command') or 0, HexCodes=1)  # command
        raw += int_to_four_hex(kwargs.get('ntstatus') or 0)  # NT STATUS  --> 00000000 is SUCCESS
        raw +=  HexCodeInteger(kwargs.get('flags') or 0, HexCodes=1 )  # Flags
        raw += HexCodeInteger(kwargs.get('flags2') or 0, HexCodes=2 )
        raw += int_to_two_hex(0)  # PIDHIGH
        raw += HexCodeInteger(kwargs.get('signature') or 0, HexCodes=8)  # Signature
        raw += int_to_two_hex(0)  # reserved
        raw += int_to_two_hex(kwargs.get('tid') or 0)  # tid
        raw += int_to_two_hex(kwargs.get('pid') or 0)   # Pid
        raw += int_to_two_hex(kwargs.get('uid') or 0) # userid
        raw += int_to_two_hex(kwargs.get('mid') or 0)  # m ID
        return raw
