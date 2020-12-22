from TCP_flow_control import *
from Scapy_Control import ListRandomizer, GenerateRandomIp, GenerateRandomMac, RandomSafePortGenerator
import os
from time import sleep
import random
import socket
from mimetypes import MimeTypes

class HTTPS_support():
    def __init__(self):
        self.Packets = []
        self.Flows={}
    def Setup_Flow(self,
                   Flow='HTTPS_TRAFFIC', #'FTP_COMMAND' #'FTP_DATA'
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
                               InitServerSeq = self.InitServerSeq,
                               vlanTag=self.vlanTag,
                               ssl_tls = self.subject,
                               issuer=self.issuer,
                               version=self.version,)
        self.Flows[Flow] = FlowObject


    def SetVariables(self,
                     METHOD = 'GET',
                     UserAgent = 'curl/7.35.0',
                       dmac = '11:22:33:44:55:66',
                       smac = '22:33:44:55:66:77',
                       TYPE= 'IPv4',
                       src = '1.1.1.1',
                       dst = '2.2.2.2',
                       srcv6 = None,
                       dstv6 = None,
                       sport = 1234,
                       dport = 80,
                       INTF = 'wlan0',
                       FILES = ['/data/files/Malicious_DOC.doc'],
                       InitClientSeq=1,
                       InitServerSeq=1,
                       rlength = 1500,
                     Verbose = None,
                     vlanTag=None,
                     subject=None,
                     issuer=None,
                     version=None,
                     ):
        self.subject=subject
        self.issuer=issuer
        self.version=version
        self.METHOD = METHOD
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
        self.InitClientSeq=InitClientSeq
        self.InitServerSeq=InitServerSeq
        self.rlength = rlength
        self.Verbose = Verbose
        self.vlanTag=vlanTag
        self.GetMime(FILE=self.FILES[0])
        self.subject = subject
        self.issuer = issuer
        self.version=version

    def GetLength(self,
                  CalcLengthof=None):
        self.LEN = 0
        if isinstance(self.FILES, str):
            if self.FILES.lower() == 'none':
                self.LEN = 0
        if isinstance(self.FILES,tuple) or isinstance(self.FILES,list):
            if 'none' in self.FILES:
                self.LEN = 0
            else:
                for FILE in self.FILES:
                    self.LEN += len(open(FILE, 'rb').read())+int(self.addlen)
        if self.FILES == None:
            self.LEN = 0
        return self.LEN

    def GetMime(self,
                FILE = None):
        mime = MimeTypes()
        if FILE == None:
            FILE = self.FILES
        self.mType = 'application/octet-stream'
        if isinstance(FILE,str):
            self.mType= mime.guess_type(FILE)[0] or 'application/octet-stream'
        if isinstance(FILE,tuple) or isinstance(self.FILES,list):
            self.mType= mime.guess_type(FILE[0])[0] or 'application/octet-stream'
        return self.mType

    def SendRequestHeaders(self,
                           Flow = 'HTTPS',
                           ):
        DATA = []
        DATA.append('%s someserver.com\r\n' %(self.METHOD) ) #path and version wrpcap
        DATA.append('Accept: */*\r\n') #accept

        data = ''
        for value in DATA:
            data += value

        # send client headers
        self.Flows[Flow].ConStruct_Packet_With_Data(fromSrc = True,
                                                    data= data)

        # send server acknowledge
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = False)



    def SendResponseHeaders(self,
                            Flow = 'HTTPS',
                            Flags = 'PA',
                            **kwargs):

        if self.Flows[Flow].LastRawSize != 0:
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = False)
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = True)

        # define nessessary headers
        DATA = ['200 OK\r\n',
                'Server: Nathan Is Awesome\r\n',
                'Date: %s\r\n' %str(time.asctime()),
                'Content-type: applicaion-data\r\n',
                ]

        data = ''
        for value in DATA:
            data += value

        self.Flows[Flow].ConStruct_Packet_With_Data(fromSrc = False,
                                                         data= data,
                                                         Flags=Flags)
        # client acknowledge
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = True)

    def HTTPS_TEST(self):
        #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTPS')
        FILE = self.FILES[0]

        #step 2 Send Client Request Headers
        #dont scrample the request headers
        self.SendRequestHeaders(Flow = 'HTTPS')


        if self.METHOD == 'GET':
            #STEP 3 SERVER RESONSE HEADERS
            #dont scrample the response headers
            self.SendResponseHeaders(Flow = 'HTTPS')


            #STEP 4 SERVER SEND file
            self.Flows['HTTPS'].Download_File(FILE = FILE,
                                              rlength = self.rlength)
        else:
            #STEP 3 Client Send File
            self.Flows['HTTPS'].Upload_File(FILE = FILE,
                                          rlength = self.rlength)


            #STEP 4 SERVER RESPONCE HEADERS
            self.SendResponseHeaders(Flow = 'HTTPS')

        #STEP 5 Finish up flow
        self.Flows['HTTPS'].Fin_Flow()
        self.Packets += self.Flows['HTTPS'].packets
        self.Flows['HTTPS'].packets = []
        return self.Packets




if __name__ == '__main__':
    self = HTTPS_Support()
    self.SetVariables(METHOD = 'GET',
                          UserAgent = 'curl/7.35.0',
                          dmac = '11:22:33:44:55:66',
                          smac = '22:33:44:55:66:77',
                          src = '1.1.1.1',
                          dst = '2.2.2.2',
                          sport = 1234,
                          dport = 4443,
                          INTF = 'wlan0',
                          FILES = ['../TestFiles/Malicious_DOC.doc'],
                          InitClientSeq=1,
                          InitServerSeq=1,
                          rlength = 1500,
                          Verbose = None,
                          vlanTag=None,
                          ssl_tls=True,
                          subject=None,
                          issuer=None,
                     version=None,
                     #DISPSITION =[{'name':'file'}, {'filename':'post.file'}],
                          )
