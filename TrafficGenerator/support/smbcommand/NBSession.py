
from Scapy_Control import *

class NBSession():
    def add_raw_to_nb(self,
                      raw=None,):
        NB = '\x00'  # message type
        NB += '\x00'  # flags
        NB += int_to_two_hex(len(raw), Swap=False)  # size

        raw = NB + raw
        return raw

