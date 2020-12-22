from Scapy_Control import *
from TCP_flow_control import *
from smb2command.Create_Close import *
from smb2command.NBSession import *
from smb2command.Negotiate import *
from smb2command.Read import *
from smb2command.SMB2Header import *
from smb2command.SessionSetup import *
from smb2command.Tree import *
from smb2command.Write import *


class SMB2_Support(SMB2Header, SessionSetup, Negotiate, Tree, Create_Close, Read, Write, NBSession):
    def __init__(self):
        self.Packets = []
        self.Flows = {}

    def Setup_Flow(self,
                   Flow='SMB_TRAFFIC',  # 'FTP_COMMAND' #'FTP_DATA'
                   ):
        FlowObject = TCP_flow_control()
        FlowObject.Sync_Flow(dmac=self.dmac,
                             smac=self.smac,
                             TYPE=self.TYPE,
                             src=self.src,
                             dst=self.dst,
                             srcv6=self.srcv6,
                             dstv6=self.dstv6,
                             dport=self.dport,
                             sport=self.sport,
                             InitClientSeq=self.InitClientSeq,
                             InitServerSeq=self.InitServerSeq,
                             vlanTag=self.vlanTag)
        self.Flows[Flow] = FlowObject

    def SetVariables(self,
                     dmac='11:22:33:44:55:66',
                     smac='22:33:44:55:66:77',
                     TYPE='IPv4',
                     src='1.1.1.1',
                     dst='2.2.2.2',
                     srcv6=None,
                     dstv6=None,
                     sport=1234,
                     dport=139,
                     INTF='wlan0',
                     FILES=['/opt/TrafficGen/TestFiles/Malicious_DOC.doc'],
                     InitClientSeq=1,
                     InitServerSeq=1,
                     rlength=1500,
                     Verbose=None,
                     DISPSITION=False,
                     vlanTag=None,
                     vlanTagType=0,
                     UID=None,
                     PID=None,
                     TID=None,
                     MID=None,
                     AlterMID=True,
                     CLientDomain='ClientD0M',
                     ClientUser='ClientUser123',
                     ClientHost='ClienTHo',
                     NBDomain='2008DOM',
                     NBComp='2008COMP',
                     DNSDoman='2008DNSDOM',
                     DNSCOMP='2008DNCCOMP',
                     DNSTREE= '2008DNSTREE',
                     tree=None,
                     Delete=False):
        self.Delete=Delete
        self.DNSTREE=DNSTREE
        self.leasekey = RamdomRawData(size=16)
        self.tree=tree or '\\\\%s\\path' %NBDomain
        self.CLientDomain=CLientDomain
        self.ClientUser=ClientUser
        self.ClientHost=ClientHost
        self.NBDomain=NBDomain
        self.NBComp=NBComp
        self.DNSDoman=DNSDoman
        self.DNSCOMP=DNSCOMP
        self.AlterMID = AlterMID
        self.UID = UID or random.randint(1, 5000)
        self.PID = PID or random.randint(1, 5000)
        self.TID = TID or random.randint(1, 5000)
        self.MID = MID or random.randint(1, 255)
        self.SessionKey = RamdomRawData(size=16)


        self.GUID = RamdomRawData(size=16)
        self.ClientGuid = RamdomRawData(size=16)

        self.dmac = dmac
        self.smac = smac
        self.TYPE = TYPE
        self.src = src
        self.dst = dst
        self.srcv6 = srcv6
        self.dstv6 = dstv6
        self.sport = sport
        self.dport = dport
        self.INTF = INTF
        self.FILES = FILES
        self.InitClientSeq = InitClientSeq
        self.InitServerSeq = InitServerSeq
        self.rlength = rlength
        self.Verbose = Verbose
        self.DISPSITION = DISPSITION
        self.vlanTag = vlanTag
        self.vlanTagType = int(vlanTagType)



    def Negotiate(self,
                  Flow='SMB',
                  **kwargs):


        if self.AlterMID: self.MID += 1
        self.NegotiateSMB2Request(Flow=Flow,
                              **kwargs)
        self.NegotiateSMB2Response(Flow=Flow,
                               **kwargs)


    def SessionSetup(self,
                  Flow='SMB',
                  **kwargs):



        if self.AlterMID: self.MID += 1

        self.SessionSetupSMB2Request_NTMSSP_NEGOTIATE(Flow=Flow,
                                                      **kwargs)

        self.SessionSetupSMB2ResponceNeedAuthenticataion(Flow=Flow,
                                                         **kwargs)

        if self.AlterMID: self.MID += 1

        self.SessionSetupSMB2RequestUser(Flow=Flow,
                                         **kwargs)

        self.SessopmSetupResponseFinal(Flow=Flow,
                                       **kwargs)


    def TreeConnect(self,
                    Flow='SMB',
                    **kwargs):
        if self.AlterMID: self.MID += 1
        self.TreeRequest(Flow=Flow,
                         **kwargs)
        self.TreeResponse(Flow=Flow,
                          **kwargs)


    def Create(self,
               Flow='SMB',
               **kwargs):

        if self.AlterMID: self.MID += 1
        self.CreateFileRequest(Flow=Flow,
                               **kwargs)

        self.CreateFileResponse(Flow=Flow,
                            **kwargs)

    def Close(self,
              Flow='SMB',
              **kwargs):
        if self.AlterMID: self.MID += 1
        self.CloseFileRequest(Flow=Flow,
                               **kwargs)
        self.CloseFileResponse(Flow=Flow,
                               **kwargs)


    #higher level flows

    def Delete_File(self,
               Flow='SMB',
               **kwargs):
        FILES = []
        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:
            self.ActiveFile = FILE
            self.FID = random.randint(1, 255)
            self.Delete=True
            self.Create(Flow=Flow,
                        **kwargs)
            self.Close(Flow=Flow,
                       **kwargs)

    def Read(self,
              Flow='SMB',
              **kwargs):
        FILES = []
        if isinstance(self.FILES,basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:
            self.ActiveFile = FILE
            self.FID = random.randint(1, 255)
            self.Create(Flow=Flow,
                        **kwargs)

            if self.AlterMID: self.MID += 1
            self.ReadRequest(Flow=Flow,
                             **kwargs)

            self.ReadResponse(Flow=Flow,
                              **kwargs)
            self.Close(Flow=Flow,
                       **kwargs)


    def Write(self,
              Flow='SMB',
              **kwargs):
        FILES = []
        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:
            self.ActiveFile = FILE
            self.FID = random.randint(1, 255)
            self.Create(Flow=Flow,
                        **kwargs)

            if self.AlterMID: self.MID += 1
            self.WriteRequest(Flow=Flow,
                             **kwargs)

            self.WriteResponse(Flow=Flow,
                              **kwargs)

            self.Close(Flow=Flow,
                       **kwargs)

    def SMB2Test(self,
                Flow='SMB',
                Negotiate=True,
                Session=True,
                Tree=True,
                Read=False,
                Write=False,
                Delete=False,
                **kwargs):

        # Lets SyncFlow
        self.Packets = []
        self.Setup_Flow(Flow=Flow)

        # com negotiate
        if Negotiate: self.Negotiate()
        if Session: self.SessionSetup(**kwargs)
        if Tree: self.TreeConnect(**kwargs)
        if Read: self.Read(File=self.FILES)  # test.file)
        if Write: self.Write(File=self.FILES)
        if Delete: self.Delete_File()

        self.Packets = self.Flows[Flow].packets

        self.Flows['SMB'].Fin_Flow()
        return self.Packets


if __name__ == '__main__':
    self = SMB2_Support()
    self.SetVariables(src=GenerateRandomIp(),
                      dst=GenerateRandomIp(),
                      FILES=['/opt/TrafficGen/TestFiles/Malicious_DOC.doc',
                             '/opt/TrafficGen/TestFiles/Benign_DOC.doc',
                             ],
                      #Delete=True,
                      )
    packets = self.SMB2Test(Session=True,
                            Tree=True,
                            create=True,
                            Read=True,
                            Write=True,
                            Close=True,
                            )
    # packets[3].show2()
    wrpcap('/home/nathan/test.pcap', packets)


