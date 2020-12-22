from Scapy_Control import *

class SMB2Header(object):
    def SMB2Header(self,
                   **kwargs):
        ### SMB2 head
        length = kwargs.get('length') or 64
        raw = '\xfeSMB'  # smb2 component
        raw += int_to_two_hex(length)  # header length
        raw += int_to_two_hex(kwargs.get('credit') or 0)  # credit charge
        raw += int_to_four_hex(kwargs.get('ntstatus') or 0)  # NT STATUS  --> 00000000 is SUCCESS
        raw += int_to_two_hex(kwargs.get('command') or 0)  # 00 is negoticate protocol
        raw += int_to_two_hex(kwargs.get('credits') or 0)  # credits granted
        raw += int_to_four_hex(kwargs.get('flags') or 0)  # Flags
        raw += int_to_four_hex(kwargs.get('chainoffset') or 0)  # chain offset'
        raw += int_to_eight_hex(kwargs.get('mid') or 0)  # MessageID??
        raw += int_to_four_hex(kwargs.get('pid') or 0)  # PIDHIGH
        raw += int_to_four_hex(kwargs.get('tid') or 0)  # tree id
        raw += int_to_eight_hex(kwargs.get('sessionid') or 0)  # Session ID
        raw += HexCodeInteger(kwargs.get('signature') or 0, HexCodes=16)  # Signature


        assert len(raw) == length
        return raw

if __name__ == '__main__':
    class xxx(SMB2Header):
        x = 5
    c = xxx()
    c.SMB2Header(flags=9)
