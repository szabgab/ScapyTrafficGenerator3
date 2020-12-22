from TCP_flow_control import *
from smbcommand.SMB_COM import *
from smbcommand.Negotiate import *
from smbcommand.SMBHeader import *
from smbcommand.SessionSetupAndX import *
from smbcommand.TreeAndX import *
from smbcommand.Delete import *
from smbcommand.OpenAndx import *
from smbcommand.CreateAndx import *
from smbcommand.ReadAndx import *
from smbcommand.Close import *
from smbcommand.WriteAndx import *
from smbcommand.TransAction import *
from smbcommand.NBSession import *

class SMB_Support(SMBNegotiate,SMBHeader,NBSession,SessionSetupAndX,TreeAndX,Delete, OpenAndx,CreateAndx, ReadAndx, Close, WriteAndx, Trans2, Trans):
    def __init__(self):
        self.Packets = []
        self.Flows={}

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
                     FID = None,
                     MID = None,
                     AlterMID=True,
                     CLientDomain='ClientD0M',
                     ClientUser='ClientUser123',
                     ClientHost='ClienTHo',
                     NBDomain='2008DOM',
                     NBComp='2008COMP',
                     DNSDoman='2008DNSDOM',
                     DNSCOMP='2008DNCCOMP',
                     DNSTREE='2008DNSTREE',
                     serverlanmanager = 'Windows (TM) Code Name "Longhorn" ultimate 6.0',
                     servernativeos='Windows (TM) Code Name "Longhorn" ultimate 5231',
                     clientnativeos='Unix',
                     clientLanManager="Samba 3.9.0-SVN-build-11572",
                     tree='\\\\Nathan\\is\\the\greatest\\tester',
                     service = 'IPC',
                     SERVICE = "PSEXESVC"):
        self.AlterMID=AlterMID
        self.UID = UID or random.randint(1,5000)
        self.PID = PID or random.randint(1, 5000)
        self.TID = TID or random.randint(1, 5000)
        self.FID = FID or random.randint(1, 255)
        self.MID = MID or random.randint(1, 255)
        self.GUID=RamdomRawData(size=16)
        self.Service = SERVICE

        #print 'UID', self.UID
        #print 'PID', self.PID
        #print 'TID', self.TID
        #print 'FID', self.FID
        #print 'MID', self.MID
        self.dmac = dmac
        self.smac = smac
        self.TYPE = TYPE
        self.src = src or GenerateRandomIp()
        self.dst = dst or GenerateRandomIp()
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
        self.subcommand = 0x00

        self.NBDomain = padTextafter(NBDomain)
        self.NBComp = padTextafter(NBComp)
        self.DNSDoman = padTextafter(DNSDoman)
        self.DNSCOMP = padTextafter(DNSCOMP)
        #self.DNSTREE = padTextafter('VISTA2')
        self.servernativeos = padTextafter(servernativeos)
        self.serverlanmanager = padTextafter(serverlanmanager)
        #self.clientnativeos=padTextafter(clientnativeos)
        self.clientnativeos=clientnativeos
        #self.CLientDomain = padTextafter(CLientDomain)
        #self.ClientUser = padTextafter(ClientUser)
        #self.ClientHost = padTextafter(ClientHost)
        self.CLientDomain = CLientDomain
        self.ClientUser = ClientUser
        self.ClientHost = ClientHost
        self.SessionKey = RamdomRawData(size=16)
        self.clientLanManager=clientLanManager
        self.tree = tree
        self.service = service
        self.context_handle = HexCodeInteger(0, HexCodes=4) + RamdomRawData(size=16)
        self.CallID = 1
        self.Opnum = 15
        self.Pipename='\\PIPE\\'

        self.ServerCredentials = {
            'nbd': {'type': 2, 'value': self.NBDomain},
            'nbc': {'type': 1, 'value': self.NBComp},
            'dnsd': {'type': 4, 'value': self.DNSDoman},
            'dnsn': {'type': 3, 'value': self.DNSCOMP},
            # 'dnst': {'type': 5, 'value': self.DNSTREE},
            'timestamp': {'type': 7, 'value': HexCodeInteger(int(time.time() * 1000), HexCodes=8)},
        }

        self.ClientCredentials = {'NTMLChallenge': RamdomRawData(size=8),  # NTMLChallenge
                                  'NTMLResponse': RamdomRawData(size=24), #
                                'CDoman': padTextafter(CLientDomain),
                                'CUser': padTextafter(ClientUser),
                                'CHost': padTextafter(ClientHost),
                                'SessionKey': self.SessionKey,
                             }


    def close(self,
              Flow='SMB',
              **kwargs
              ):

        NB = NBTSession(TYPE="Session Message")
        SMBRQ = SMBSession_Setup_AndX_Request(Command=SMB_COM_CLOSE,
                                              TID=self.TID,
                                              UID=self.UID,
                                              PID=self.PID,
                                              AndXCommand=self.FID ,
                                              )

        RQ = NB / SMBRQ
        RQ[NBTSession].LENGTH = long(len(RQ[NBTSession].payload))

        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=True,
                                                       Flags='PA',
                                                       AttachLayers=RQ)

        # first packet acknowledge
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       )

        NB = NBTSession(TYPE="Session Message")
        SMBSXRS = SMBSession_Setup_AndX_Response(Command=SMB_COM_CLOSE,
                                                 AndXCommand=SMB_COM_NONE,
                                                 TID=self.TID,
                                                 UID=self.UID,
                                                 PID=self.PID,
                                                 #Action=kwargs.get('FID') or 1,
                                                 )

        SMBSXRESPONSE = NB / SMBSXRS
        SMBSXRESPONSE[NBTSession].LENGTH = long(len(SMBSXRESPONSE[NBTSession].payload))

        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc=False,
                                                       Flags='PA',
                                                       AttachLayers=SMBSXRESPONSE)

    def Negotiate(self,
                  Flow='SMB',
                  **kwargs):

        if self.AlterMID: self.MID += 1
        self.NegotiateRequest(Flow=Flow,
                              **kwargs)
        self.NegotiateResponse(Flow=Flow,
                               **kwargs)



    def SessionSetup(self,
                     **kwargs):
        if self.AlterMID: self.MID += 1

        self.SessionSetupandxInitRequest(Flow='SMB',
                                         **kwargs)

        self.SessionSetupandxNeedAuthResopnse(Flow='SMB',
                                              **kwargs)

        if self.AlterMID: self.MID += 1

        self.SessionSetupandxAuthRequest(Flow='SMB',
                                         **kwargs)

        self.SessionSetupandxFinalResopnse(Flow='SMB',
                                           **kwargs)

    def SessionTreeConnect(self,
                           Flow='SMB',
                           **kwargs):


        if self.AlterMID: self.MID += 1
        self.TreeConnectRequest(Flow='SMB',
                                **kwargs)
        self.TreeConnectResponse(Flow='SMB',
                                 **kwargs)

    def Delete(self,
               Flow='SMB',
               **kwargs):
        FILES = []
        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:
            if self.AlterMID: self.MID += 1
            self.ActiveFile = FILE
            self.DeleteRequest(Flow=Flow,
                               **kwargs)

            self.DeleteResponse(Flow=Flow,
                               **kwargs)


    # currently create and x requests are used much mor than this
    def Open(self,
             Flow='SMB',
             **kwargs):
        FILES = []
        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:

            if self.AlterMID: self.MID += 1
            self.ActiveFile=FILE

            self.OpenAndxRequest(Flow=Flow,
                                 **kwargs)
            self.OpenAndxResponse(Flow=Flow,
                              **kwargs)
            self.FID += 1

    # print 'done open'
    def Create(self,
             Flow='SMB',
             **kwargs):
        FILES = []

        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:

            if self.AlterMID: self.MID += 1
            self.ActiveFile = FILE

            self.CreateAndxRequest(Flow=Flow,
                                 **kwargs)
            self.CreateAndxResponse(Flow=Flow,
                                  **kwargs)
            self.FID += 1

    def Trans2(self,
               Flow='SMB',
               **kwargs):
        FILES = []

        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:

            if self.AlterMID: self.MID += 1
            self.ActiveFile = FILE

            self.CreateAndxRequest(Flow=Flow,
                                   **kwargs)
            self.CreateAndxResponse(Flow=Flow,
                                    **kwargs)

            for i in range(18):
                if self.AlterMID: self.MID += 1
                self.subcommand = i
                self.Trans2Request(Flow=Flow,
                                   **kwargs)

                self.Trans2Response(Flow=Flow,
                                    **kwargs)

            self.FID += 1

    def ServiceAttack(self,
                      Flow='SMB',
                      **kwargs):


        ##write the file
        if self.AlterMID: self.MID += 1
        self.ActiveFile = '%s.exe' %self.Service

        self.CreateAndxRequest(Flow=Flow,
                               **kwargs)
        self.CreateAndxResponse(Flow=Flow,
                                **kwargs)
        self.WriteAndxRequest(Flow=Flow,
                              **kwargs)
        self.WriteAndxResponse(Flow=Flow,
                               **kwargs)
        self.CloseRequest(Flow=Flow,
                          **kwargs)
        self.CloseResponse(Flow=Flow,
                           **kwargs)
        self.FID += 1



        #start the service control and start filepath as file
        if self.AlterMID: self.MID += 1
        self.subcommand = 0x26
        self.ActiveFile = '\\svcctl'

        self.CreateAndxRequest(Flow=Flow,
                               disposition=5,
                               **kwargs)
        self.CreateAndxResponse(Flow=Flow,
                                createAction=2,
                                **kwargs)


        if self.AlterMID: self.MID += 1
        self.WriteAndxBindRequest(Flow=Flow,
                                  **kwargs)

        self.WriteAndxResponse(Flow=Flow,
                               **kwargs)

        self.ServiceFlow(Flow=Flow,
                           **kwargs)

        self.CloseRequest(Flow=Flow,
                          **kwargs)


        self.CloseResponse(Flow=Flow,
                           **kwargs)


    def Read(self,
               Flow='SMB',
               **kwargs):
        FILES = []

        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:

            if self.AlterMID: self.MID += 1
            self.ActiveFile = FILE

            self.CreateAndxRequest(Flow=Flow,
                                   **kwargs)
            self.CreateAndxResponse(Flow=Flow,
                                    **kwargs)
            self.ReadAndxRequest(Flow=Flow,
                                 **kwargs)
            self.ReadAndxResponse(Flow=Flow,
                                 **kwargs)
            self.CloseRequest(Flow=Flow,
                              **kwargs)
            self.CloseResponse(Flow=Flow,
                              **kwargs)
            self.FID += 1

    def Write(self,
              Flow='SMB',
              **kwargs):
        FILES = []

        if isinstance(self.FILES, basestring):
            FILES.append(self.FILES)
        else:
            FILES = self.FILES

        for FILE in FILES:

            if self.AlterMID: self.MID += 1
            self.ActiveFile = FILE

            self.CreateAndxRequest(Flow=Flow,
                                   **kwargs)
            self.CreateAndxResponse(Flow=Flow,
                                    **kwargs)
            self.WriteAndxRequest(Flow=Flow,
                                 **kwargs)
            self.WriteAndxResponse(Flow=Flow,
                                  **kwargs)
            self.CloseRequest(Flow=Flow,
                              **kwargs)
            self.CloseResponse(Flow=Flow,
                               **kwargs)
            self.FID += 1

    def SMBTest(self,
                Flow='SMB',
                Negotiate=True,
                Session=True,
                Tree=True,
                Trans2=False,
                ServiceAttack=False,
                Delete=False,
                Open=False,
                Read=False,
                Write=False,
                Close=False,
                **kwargs):
        #Lets SyncFlow
        self.Packets = []
        self.Setup_Flow(Flow=Flow)

        #com negotiate
        if Negotiate: self.Negotiate()
        if Session: self.SessionSetup(**kwargs)
        if Tree: self.SessionTreeConnect(**kwargs)
        if Delete: self.Delete(**kwargs)
        #if Open: self.Open()
        #if Create: self.Create()
        if Read: self.Read(File=self.FILES) #test.file)
        if Write:self.Write(File=self.FILES)
        if ServiceAttack:self.ServiceAttack()#File=self.FILES)
        if Trans2: self.Trans2(File=self.FILES)
        if Close: self.close()

        self.Packets = self.Flows[Flow].packets

        self.Flows['SMB'].Fin_Flow()
        return self.Packets


if __name__=='__main__':
    self =SMB_Support()
    self.SetVariables(src=GenerateRandomIp(),
                      dst=GenerateRandomIp(),
                      FILES=['/opt/TrafficGen/TestFiles/Malicious_DOC.doc',
                             #'/opt/TrafficGen/TestFiles/Benign_DOC.doc',
                             ],
                      CLientDomain='ClientD0M',
                      ClientUser='ClientUser123',
                      ClientHost='ClienTHo',
                      NBDomain='2008DOM',
                      NBComp='2008COMP',
                      DNSDoman='2008DNSDOM',
                      DNSCOMP='2008DNCCOMP',
                      DNSTREE='2008DNSTREE',
                      serverlanmanager='Windows (TM) Code Name "Longhorn" ultimate 6.0',
                      servernativeos='Windows (TM) Code Name "Longhorn" ultimate 5231',
                      SERVICE='fionasdo'
                      )
    packets = self.SMBTest(ServiceAttack=True)
    #packets[3].show2()
    wrpcap('/home/nathan/test.pcap', packets)

