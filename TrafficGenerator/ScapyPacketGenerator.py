from support.FTP_Support import *
from support.HTTP_Support import *
from support.HTTPS_support import *
from support.SMTP_Support import *
from support.DNS_Support import *
from support.TCP_Basic_Support import *
from support.TemplateSupport import *
from support.Gre_Encapsulate import *
from support.SMB_Support import *
from support.VlanTag import *
from support.SMB2_Support import *


class ScapyPacketGenerator():
    create_pcap_only = os.getenv('CREATE_PCAP_ONLY')
    def __init__(self):
        self.INTF = None
        self.Packets = []
        ## template imports are
        self.Template = TemplateSupport()
        self.TCP = TCP_Basic_Support()
        self.SMTP = SMTP_Support()
        self.DNS = DNS_Support()
        self.FTP = FTP_Support()
        self.HTTPS = HTTPS_support()
        self.HTTP = HTTP_Support()
        self.SMB = SMB_Support()
        self.SMB2 = SMB2_Support()

    def SetupInterface(self,
                       INTF = None,
                       ):
        self.INTF= INTF
    def EncasulateGre(self,
                       chksum_present=1,
                       proto=0x0800,
                       ):
        Gre = Gre_Encapsulate(self.Packets,
                        chksum_present = chksum_present,
                        proto = proto)
        self.Packets = Gre.packets
    def EncasulateVlan(self,
                      vlanTag=1,
                       vlanTagType=0,
                      ):
        vlan = VlanTag(self.Packets,
                      vlanTag=vlanTag,
                       vlanTagType=vlanTagType)

        self.Packets = vlan.packets
    def SendPackets(self,
                    Verbose = None,
                    outfile = None):
        if self.create_pcap_only:
            if isinstance(self.create_pcap_only, basestring):
                if self.create_pcap_only != '0':
                    wrpcap(self.create_pcap_only, self.Packets)
                    return

        #print self.Packets
        if Verbose == None: #dont set verbose
            sendp(self.Packets,iface=self.INTF)
        else:
            print 'sending %i packets a sec' %Verbose
            assert type(Verbose) == int, 'Verbose must be defined as integer'
            sendpfast(self.Packets,iface=self.INTF,pps=Verbose)

        if outfile != None:
            wrpcap(outfile,self.Packets)
