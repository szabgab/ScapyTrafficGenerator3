from TCP_flow_control import *



class  TCP_Basic_Support():
    def __init__(self):
        self.Packets = []
        self.Flows = {}
    def Setup_Flow(self,
                   Flow='TCP_BASIC', #'FTP_COMMAND' #'FTP_DATA'
                   ):

        FlowObject = TCP_flow_control()
        FlowObject.Sync_Flow(dmac = self.dmac,
                               smac = self.smac,
                               TYPE= self.TYPE,
                               src = self.src,
                               dst = self.dst,
                             srcv6 = self.srcv6,
                             dstv6 = self.dstv6,
                               dport = self.dport,
                               sport = self.sport,
                               InitClientSeq = self.InitClientSeq,
                               InitServerSeq = self.InitServerSeq)
        self.Flows[Flow] = FlowObject
        #print 'flow object created', FlowObject


    def SetVariables(self,
                     dmac = '11:22:33:44:55:66',
                     smac = '22:33:44:55:66:77',
                     TYPE= 'IPv4',
                     src = '1.1.1.1',
                     dst = '2.2.2.2',
                     srcv6 = None,
                     dstv6 = None,
                     sport = 1234,
                     dport = 80,
                     INTF = 'veth1',
                     InitClientSeq=1,
                     InitServerSeq=1,
                     SendData=[],
                     vlanTag=None):
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
        self.SendData = SendData
        self.InitClientSeq=InitClientSeq
        self.InitServerSeq=InitServerSeq
        self.vlanTag=vlanTag

    def Test(self):
        #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='TCP')

        #print 'FlowObject', self.Flows['TCP']
        #step 2 send data
        for data in self.SendData:
            clientData, ServerData = data
            #print 'client data', clientData
            #print 'server data', ServerData
            if clientData:
                self.Flows['TCP'].ConStruct_Packet_With_Data(fromSrc=True,
                                                                       data=clientData)
            if ServerData:
                self.Flows['TCP'].ConStruct_Packet_With_Data(fromSrc=False,
                                                                       data=ServerData)
            else:
               self.Flows['TCP'].ConStruct_Packet_Without_Data(fromSrc=False)

        #step 3 fin
        #STEP 5 FIN
        self.Flows['TCP'].Fin_Flow()
        self.Packets += self.Flows['TCP'].packets
        self.Flows['TCP'].packets = []


        return self.Packets

