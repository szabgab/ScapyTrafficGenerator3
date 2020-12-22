from TCP_flow_control import *
from Scapy_Control import ListRandomizer, GenerateRandomIp, GenerateRandomMac, RandomSafePortGenerator
import os
from time import sleep
import random
import socket
from mimetypes import MimeTypes

class HTTP_Support():
    def __init__(self):
        self.Packets = []
        self.Flows={}
    def Setup_Flow(self,
                   Flow='HTTP_TRAFFIC', #'FTP_COMMAND' #'FTP_DATA'
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
                               ssl_tls = self.ssl_tls,
                             timeoffset=self.timeoffset)
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
                       FILES = ['/opt/TrafficGen/TestFiles/Malicious_DOC.doc'],
                       InitClientSeq=1,
                       InitServerSeq=1,
                       HTTPVERSION= 'HTTP/1.1',
                       ServerResponce = 'HTTP/1.1 200 OK',
                       ServerName = 'Nathans_HTTP_SERVER/0.1 Python/2.7.6',
                       GZIP = False,
                       CHUNKED = False,
                       rlength = 1500,
                     TIME = 60, #60 seconds
                     Verbose = None,
                     DISPSITION = False,
                     HOST = None,
                     URLBASE = None,
                     requestHeaders=[],
                     responseHeaders=[],
                     chain=[],
                     randomized = False,
                     DATAONLY = 0,
                     vlanTag=None,
                     ssl_tls=False,
                     vlanTagType=0,
                     timeoffset=0):
        self.ssl_tls=ssl_tls
        self.METHOD = METHOD
        self.UserAgent = UserAgent
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
        self.HTTPVERSION= HTTPVERSION
        self.ServerResponce = ServerResponce
        self.ServerName = ServerName
        self.GZIP = GZIP
        self.CHUNKED = int(CHUNKED)
        self.rlength = rlength
        self.TIME = int(TIME)
        self.Verbose = Verbose
        self.DISPSITION = DISPSITION
        self.vlanTag=vlanTag
        self.vlanTagType = int(vlanTagType)
        self.timeoffset=int(timeoffset)
        print 'http support flow contorl set vlantag', self.vlanTag, 'with tag type',self.vlanTagType

        if URLBASE == None:
            self.URLBASE = self.FILES[0]
        else:
            self.URLBASE = URLBASE
        if HOST == None:
            self.HOST = self.dst
        else:
            self.HOST = HOST
        self.CHAIN = []
        if isinstance(chain,basestring):
            self.CHAIN.append(chain.split(':'))
        for value in chain:
            self.CHAIN.append(value.split(':'))
        if type(requestHeaders) == str:
            self.requestHeaders= [requestHeaders]
        else:
            self.requestHeaders=requestHeaders
        if type(responseHeaders) == str:
            self.responseHeaders=responseHeaders
        else:
            self.responseHeaders=responseHeaders
        self.randomized = randomized
        if randomized != False:
            self.addlen = int(randomized)
        else:
            self.addlen = 0
        if DATAONLY == 0:
            self.GetLength(CalcLengthof=self.FILES)
        else:
           self.LEN = DATAONLY
        self.GetMime(FILE=self.FILES[0])

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
                           Flow = 'HTTP',
                           ):

        DATA = []
        # define http Get request headers
        if self.METHOD == 'GET':
            DATA = []
            DATA.append('%s %s %s\r\n' %(self.METHOD,self.URLBASE,self.HTTPVERSION))  #path and version wrpcap
            DATA.append('User-Agent: %s\r\n' %self.UserAgent) #user agent
            DATA.append('Host: %s\r\n' %self.HOST)  #destination of host
            DATA.append('Accept: */*\r\n') #accept

            # define headers if requesting chunked transfer
            if self.CHUNKED != False:
                assert type(int(self.CHUNKED)) == int, 'Chunked must be definde as False or integer value, it is %s' %str(type(self.CHUNKED))      
                #DATA.append('Transfer-Encoding: chunked\r\n') #chunked
                #self.rlength = self.CHUNKED
                
            # define headers if requesting gzip transfer
            if self.GZIP == True:
                DATA.append('accept-encoding:gzip\r\n') #gzip type

            # add additional request headers
            if isinstance(self.requestHeaders,basestring):
                self.requestHeaders = [self.requestHeaders]
            for arg in self.requestHeaders:
                DATA.append('%s\r\n' %arg)
            DATA.append('\r\n')

        # define http put and post request headers
        else:

            # define headers for a regular put or post
            if self.DISPSITION == False: #binary upload
                DATA = ['%s %s %s\r\n' %(self.METHOD,self.URLBASE, self.HTTPVERSION),
                        'User-Agent: %s\r\n' %self.UserAgent,
                        'Host: %s\r\n' %self.HOST,
                        'Accept: */*\r\n',
                        'Content-length: %i\r\n' %(self.LEN),
                        'Content-Type: application/x-www-form-urlencoded\r\n',
                        ]

                # add additional request headers
                if isinstance(self.requestHeaders,basestring):
                    self.requestHeaders = [self.requestHeaders]
                for arg in self.requestHeaders:
                    DATA.append('%s\r\n' %arg) #gzip type

                #using expect 100-continue for put data
                DATA.append('Expect: 100-continue\r\n\r\n')

            # define headers for multipart put or post data
            else:
                print 'is multipart form data'
                boundary = ''.join([random.choice('0123456789abc') for i in range(12)])
                DATA = ['%s %s %s\r\n' %(self.METHOD,self.URLBASE,self.HTTPVERSION),
                        'User-Agent: %s\r\n' %self.UserAgent,
                        'Host: %s\r\n' %self.HOST,
                        'Accept: */*\r\n',
                        'Content-length: %i\r\n' %(self.LEN), #57694
                        'Expect: 100-continue\r\n',
                        ]

                # add additional request headers
                for arg in self.requestHeaders:
                    print 'adding request header', arg
                    DATA.append('%s\r\n' %arg)
                    
                DATA.append('Content-Type: multipart/form-data; boundary=----------------------------%s\r\n\r\n' %boundary)
        

        # create string for one packet for headers
        data = ''
        for value in DATA:
            data += value

        print 'request headers'
        print data

        # send client headers
        self.Flows[Flow].ConStruct_Packet_With_Data(fromSrc = True,
                                                         data= data)

        # send server acknowledge
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = False)


        # returning boundary to be used for multipart form data
        if self.DISPSITION == False:
            return
        else:
            return boundary

    def SendResponseHeaders(self,
                            Flow = 'HTTP',
                            Flags = 'PA',
                            **kwargs):

        if self.Flows[Flow].LastRawSize != 0:
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = False)
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = True)

        print 'ContentType set?', kwargs.get('ContentType')
        ContentType = kwargs.get('ContentType') or '%s' %str(self.mType)

        # define nessessary headers
        DATA = ['%s\r\n' %self.ServerResponce,
                'Server: %s\r\n' %self.ServerName,
                'Date: %s\r\n' %str(time.asctime()),
                'Content-type: %s\r\n' %ContentType,
                ]

        # add content-length if needed
        contentLength = kwargs.get('contentLength') or self.LEN
        if self.LEN > 0 and kwargs.get('NoContentLength') != True:
            DATA.append('Content-length: %i\r\n' %(contentLength))


        # add additional response headers
        for arg in self.responseHeaders:
            DATA.append('%s\r\n' %arg)

        # add headers for chunked data
        if self.CHUNKED != False:
            #print 'CHUNKED size is', CHUNKED
            assert type(int(self.CHUNKED)) == int, 'Chunked must be definde as False or integer value, it is %s' %str(type(self.CHUNKED))      
            DATA.append('Transfer-Encoding: chunked\r\n') #chunked
            #self.rlength = self.CHUNKED
            #DATA.append('Content-Length: %i\r\n' %self.CHUNKED)
            #DATA.append('Content-Disposition: attachment; filename="%s"\r\n' % os.path.basename(self.FILES[0]))
            
        # add headers for gzip data
        if self.GZIP == True:
            DATA.append('Content-Encoding:gzip\r\n') #gzip type

        # add final return at end
        DATA.append('\r\n')


        data = ''
        for value in DATA:
            data += value
        print 'response headers'
        print data

        if kwargs.get('extradata'):
            data += kwargs.get('extradata')
        # send rest
        self.Flows[Flow].ConStruct_Packet_With_Data(fromSrc = False,
                                                         data= data,
                                                         Flags=Flags)
        # client acknowledge
        self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = True)
        '''
        # send packet for each response
        for data in DATA:
            # send responce packet
            self.Flows[Flow].ConStruct_Packet_With_Data(fromSrc = False,
                                                         data= data)
            # client acknowledge
            self.Flows[Flow].ConStruct_Packet_Without_Data(fromSrc = True)
        '''
    def HTTP_REDIRECT(self):
        # lets connect
         #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]

        #step 2 Send Client Request Headers
        #dont scrample the request headers
        self.SendRequestHeaders(Flow = 'HTTP')


        #STEP 4 SERVER RESPONCE HEADERS
        self.SendResponseHeaders(Flow = 'HTTP',
                                 Flags = 'FPA',
                                 ContentType = 'html/text',
                                 contentLength=26,
                                 extradata='<html>redirecting</html>\r\n')



        #STEP 5 Finish up flow
        #fin request and acknowge in responce so just client need FA
        if self.Flows['HTTP'].Onsrc == False:
            self.Flows['HTTP'].SwapSrc_Dst()
        #client fin
        self.Flows['HTTP'].TCP.flags = 'FA'
        if self.Flows['HTTP'].LastDataSrc == True:
            self.Flows['HTTP'].TCP.seq += self.Flows['HTTP'].LastRawSize
        else:
            self.Flows['HTTP'].TCP.ack += self.Flows['HTTP'].LastRawSize
        self.Flows['HTTP'].AttachPacket(Value = 14)

        #Server acknowledge
        #self.Flows['HTTP'].SwapSrc_Dst()
        #self.Flows['HTTP'].TCP.flags = 'A'
        #self.Flows['HTTP'].TCP.ack += 1
        #self.Flows['HTTP'].AttachPacket(Value = 14)
        ##print self.TCP.seq, self.TCP.ack
        self.Packets += self.Flows['HTTP'].packets
        return self.Packets


    def HTTP_REDIRECT_CHAIN(self,
                            DATAONLY = 0):
        assert isinstance(self.CHAIN, list) or isinstance(self.CHAIN, tuple)
        # Must make the first value in the chain the initial connection


        self.Packets = []

        for i in range(len(self.CHAIN)):
            print 'chain', self.CHAIN[i]
            DIP, URL = self.CHAIN[i]
            print 'DIP', DIP
            print 'URL', URL
            host, urlsuffix = URL.split('/', 1)
            self.HOST = host
            self.URLBASE = urlsuffix
            self.dst = DIP
            self.dport += i
            self.sport += i

            self.Packets = []
            self.Setup_Flow(Flow='HTTP%i' %i)
            FILE = self.FILES[0]

            if i > 0:
                self.requestHeaders = ['Redirect:%s' %self.CHAIN[i-1][1]]

            if self.METHOD == 'GET':
                #STEP 3 SERVER RESONSE HEADERS
                #dont scrample the response headers
                self.SendResponseHeaders(Flow = 'HTTP%i' %i,
                                         ContentType="text/html",
                                         NoContentLength=True,
                                         )


                #STEP 4 SERVER SEND file
                self.Flows['HTTP%i' %i].Download_File(FILE = FILE,
                                                rlength = self.rlength,
                                                GZIP=self.GZIP,
                                                CHUNKED=self. CHUNKED,
                                                randomized = self.randomized,
                                                DATAONLY = DATAONLY)
            else:

                self.Flows['HTTP%i' %i].Upload_File(FILE = FILE,
                                          rlength = self.rlength,
                                               randomized = self.randomized,
                                          DATAONLY = DATAONLY)


                #STEP 4 SERVER RESPONCE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP%i' %i)

        #STEP 5 Finish up flow
        for i in range(len(self.CHAIN)-1,-1,-1):
            self.Flows['HTTP%i' %i].Fin_Flow()
            self.Packets += self.Flows['HTTP%i' %i].packets
            self.Flows['HTTP%i' %i].packets = []

        print 'packets in this redirect chain', len(self.Packets)
        return self.Packets
    def HTTP_WAIT_TEST(self,
                       wait=0,
                       waitlocation=[],  #'SYN', 'REQ', 'CHUNK', 'RESP', 'FIN'
                        ):
        # lets connect
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]
        sendp(self.Flows['HTTP'].packets, iface = self.INTF)


        if 'syn' in str(waitlocation).lower():
            time.sleep(wait)


        #now clear out packets
        self.Flows['HTTP'].packets = []

        # send request headers
        self.SendRequestHeaders(Flow='HTTP')
        sendp(self.Flows['HTTP'].packets, iface = self.INTF)

        if 'req' in str(waitlocation).lower():
            time.sleep(wait)


        #now clear out packets
        self.Flows['HTTP'].packets = []


        if self.METHOD == 'GET':
            # send response headers
            self.SendResponseHeaders(Flow = 'HTTP')
            sendp(self.Flows['HTTP'].packets, iface = self.INTF)

            if 'res' in str(waitlocation).lower():
                time.sleep(wait)

            self.Flows['HTTP'].packets = []
            # SERVER SEND file
            if 'chunk' in str(waitlocation).lower():
                self.Flows['HTTP'].Download_File(FILE = FILE,
                                                     rlength = self.rlength,
                                                     GZIP=self.GZIP,
                                                     CHUNKED=self. CHUNKED,
                                                    randomized = self.randomized,
                                                    wait = wait,
                                                    INTF = self.INTF)
            else:
                self.Flows['HTTP'].Download_File(FILE = FILE,
                                                     rlength = self.rlength,
                                                     GZIP=self.GZIP,
                                                     CHUNKED=self. CHUNKED,
                                                    randomized = self.randomized)

                sendp(self.Flows['HTTP'].packets, iface = self.INTF)
            self.Flows['HTTP'].packets = []

        else:
            #STEP 3 Client Send File
            if 'chunk' in str(waitlocation).lower():
                self.Flows['HTTP'].Upload_File(FILE = FILE,
                                              rlength = self.rlength,
                                              randomized = self.randomized,
                                              wait=wait,
                                              INTF = self.INTF)
            else:
                self.Flows['HTTP'].Upload_File(FILE = FILE,
                                              rlength = self.rlength,
                                              randomized = self.randomized)

                sendp(self.Flows['HTTP'].packets, iface = self.INTF)

            if 'res' in str(waitlocation).lower():
                time.sleep(wait)

            self.Flows['HTTP'].packets = []
            # SERVER RESPONCE HEADERS
            self.SendResponseHeaders(Flow = 'HTTP')
            sendp(self.Flows['HTTP'].packets, iface = self.INTF)


            self.Flows['HTTP'].packets = []

        if 'fin' in str(waitlocation).lower():
            time.sleep(wait)
        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        sendp(self.Flows['HTTP'].packets, iface = self.INTF)
        self.Flows['HTTP'].packets = []
        return





    def HTTP_NOFILE(self):
        self.Packets =[]
        #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]

        #step 2 Send Client Request Headers
        #dont scrample the request headers
        self.SendRequestHeaders(Flow = 'HTTP')


        if self.METHOD == 'GET':
            #STEP 3 SERVER RESONSE HEADERS
            #dont scrample the response headers
            self.SendResponseHeaders(Flow = 'HTTP')

        else:
            #STEP 4 SERVER RESPONCE HEADERS
            self.SendResponseHeaders(Flow = 'HTTP')

        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []

        return self.Packets

    def HTTP_SYNC_ATTACK(self,
                         syncattempts = 5,
                         requestattempts = 1,
                         NetworkUnderAttack = None):
##        print 'SYNC_ATTACK'
##        print 'sync attempts', syncattempts
##        print '404 errors', requestattempts
        #print 'type', type(NetworkUnderAttack), NetworkUnderAttack
        dstips = []
        if NetworkUnderAttack != None:
        #    print 'SYNC ATTACK for Network', NetworkUnderAttack
            IP, Netmask = NetworkUnderAttack.split('/')
            dstips= GetIpsInNetwork(ip = IP,
                                    netmask = Netmask)
        else:
            dst = GenerateRandomIp()
            dstips.append(dst)
        #print 'ips for sync try', dstips
        for requestattempt in range(requestattempts):  
            for i in range(syncattempts):
                for dst in dstips:
                    if random.randint(1,2) == 1: #just send sync but no one answer
                        for i in range(5):
                            FlowObject = TCP_flow_control()
                            FlowObject.Sync_Flow(dmac = GenerateRandomMac(),
                                             smac = self.smac,
                                             TYPE= self.TYPE,
                                             src = self.src,
                                             dst = dst,
                                             dport = 80,
                                             sport = RandomSafePortGenerator(),
                                             InitClientSeq = 1,
                                             InitServerSeq = 1,
                                             Type = 'fail',
                                                 ipid = 1+i)
                            sendp(FlowObject.packets, iface = self.INTF)
                            FlowObject.packets = []
                    else: #SYNC WITH RESET
                        for i in range(5):
                            FlowObject = TCP_flow_control()
                            FlowObject.Sync_Flow(dmac = GenerateRandomMac(),
                                             smac = self.smac,
                                             TYPE= self.TYPE,
                                             src = self.src,
                                             dst = dst,
                                             dport = 80,
                                             sport = RandomSafePortGenerator(),
                                             InitClientSeq = 1,
                                             InitServerSeq = 1,
                                             Type = 'deny')
                            #self.Packets += FlowObject.packets
                            #FlowObject.packets = []
                            sendp(FlowObject.packets, iface = self.INTF)
                            FlowObject.packets = []

            #now do the accept sync but deny request
            FlowObject = TCP_flow_control()
            FlowObject.Sync_Flow(dmac = GenerateRandomMac(),
                                     smac = GenerateRandomMac(),
                                     TYPE= self.TYPE,
                                     src = self.src,
                                     dst = GenerateRandomIp(),
                                     dport = 80,
                                     sport = RandomSafePortGenerator(),
                                     InitClientSeq = 1,
                                     InitServerSeq = 1,
                                 )
            self.Flows['HTTPrequestFail'] = FlowObject
            
            self.SendRequestHeaders(Flow = 'HTTPrequestFail')
            
            self.Flows['HTTPrequestFail'].ConStruct_Packet_With_Data(fromSrc = False,
                                                         data= 'HTTP/1.1 404 Error')
            #client acknowledge
            self.Flows['HTTPrequestFail'].ConStruct_Packet_Without_Data(fromSrc = True)

            
            #fin flow
            self.Flows['HTTPrequestFail'].Fin_Flow()
            
            self.Packets += self.Flows['HTTPrequestFail'].packets
            
            self.Flows['HTTPrequestFail'].packets = []
        
            sendp(self.Flows['HTTPrequestFail'].packets, iface = self.INTF)
            self.Flows['HTTPrequestFail'].packets = []
        #now lets continue
        self.Packets = self.HTTP_TEST()  
        return self.Packets
            
        
    def HTTP_FORCEDOWNLOAD_TEST(self):
        #step 1 Sync
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]
                    
        #step 2 Send Client Request Headers
        self.SendRequestHeaders(Flow = 'HTTP')
        
       
        #STEP 3 SERVER RESONSE HEADERS
        self.SendResponseHeaders(Flow = 'HTTP')
        #STEP 4 SERVER SEND file
        if 'error' in self.ServerResponce.lower():
            pass
        else:
            self.Flows['HTTP'].Download_File(FILE = FILE,
                                         rlength = self.rlength,
                                         GZIP=self.GZIP,
                                         CHUNKED=self. CHUNKED,
                                         randomized = self.randomized)
        
        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['HTTP'].packets
        #clear out old packets not added to main packet stream
        self.Flows['HTTP'].packets = []
       
    def HTTP_MULTIPART_TEST(self):

        #print 'multipart test'
        
        self.Packets =[]
        #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
       
        #step 2 Send Client Request Headers
        #dont scrample the request headers
        boundary = self.SendRequestHeaders(Flow = 'HTTP')
        #print 'boundary', boundary

        self.ServerResponce = 'HTTP/1.1 100 Continue'

        for File in range(len(self.FILES)):
            print 'GENTRAFFIC FOR', self.FILES[File], 'NUMBER', File +1
            mime = MimeTypes()
            mType= mime.guess_type(self.FILES[File])[0]
            if mType == None:
                mType = 'application/octet-stream'
            if File == 0:
                value = '------------------------------%s\r\nContent-Disposition: form-data; name="file"; filename="file.%i"\r\nContent-type: %s\r\n\r\n' %(boundary, File+1,str(mType))
            else:
                value = '\r\n------------------------------%s\r\nContent-Disposition:form-data; name="file"; filename="file.%i"\r\nContent-type: %s\r\n\r\n' %(boundary, File+1,str(mType)) 

            #print 'send dispo', value
            self.Flows['HTTP'].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data= value)
            #server acknowledge
            self.Flows['HTTP'].ConStruct_Packet_Without_Data(fromSrc = False)
        
            #print 'upload', File
            if 'error' in self.ServerResponce.lower():
                print 'upload error'
                pass
            else:
                print 'uploading file'
                self.Flows['HTTP'].Upload_File(FILE = self.FILES[File],
                                      rlength = self.rlength,
                                               randomized = self.randomized)


            if File+1 == len(self.FILES):
                #print 'send fin dispo\r\n------------------------------%s--\r\n' %boundary
                self.Flows['HTTP'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= '\r\n------------------------------%s--\r\n' %boundary)
                self.Flows['HTTP'].ConStruct_Packet_Without_Data(fromSrc = False)
                    
            #STEP 4 SERVER RESPONCE HEADERS
            print 'sending continue'
            self.Flows['HTTP'].ConStruct_Packet_With_Data(fromSrc = False,
                                                        data= 'HTTP/1.1 100 Continue\r\nfileLengh_of_file_%i: %i\r\n' %(File+1,len(open(self.FILES[File], 'rb').read())))
                        


        #send final responce headers
        Len = 0
        for File in self.FILES:
            #print 'len file', File, len(open(File, 'rb').read())
            Len += len(open(File, 'rb').read())
            print 'file len', Len
 
        self.SendResponseHeaders(Flow = 'HTTP')
        
              
        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []

        return self.Packets
    def HTTP_custom_response(self,
                             serverresponse = None,
                             ):

        if serverresponse != None:
            serverresponses = []
            if type(serverresponse) == str or type(serverresponse) == unicode:
                serverresponses.append(serverresponse)
            elif type(serverresponse) == list or type(serverresponse) == tuple:
                serverresponses = serverresponse
            else:
                raise TypeError('serverresponses not in proper format. is %s' %type(serverresponse))

        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        self.SendRequestHeaders(Flow = 'HTTP')

        if serverresponse != None:
            self.SendResponseHeaders(Flow = 'HTTP')
            for r in serverresponses:
                self.Flows['HTTP'].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= r)
                self.Flows['HTTP'].ConStruct_Packet_Without_Data(fromSrc = True)

        #temp work around to send file without server response

        self.Flows['HTTP'].Download_File(FILE ='/home/nathanhoisington/testing/ts-test/Tools/TrafficGenerator/TestFiles/Malicious_DOC.doc',
                                         rlength = self.rlength,
                                         GZIP=self.GZIP,
                                         CHUNKED=self. CHUNKED,
                                         randomized = self.randomized,
                                         DATAONLY = 0)


        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []

        return self.Packets



    def HTTP_TEST(self,
                  wait = 0,
                  DATAONLY = 0,
                  test=None):
        #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]
       
        #step 2 Send Client Request Headers
        #dont scrample the request headers
        self.SendRequestHeaders(Flow = 'HTTP')


        if self.METHOD == 'GET':
            #STEP 3 SERVER RESONSE HEADERS
            #dont scrample the response headers
            self.SendResponseHeaders(Flow = 'HTTP')
            
            
            #STEP 4 SERVER SEND file
             
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Download_File(FILE = FILE,
                                            rlength = self.rlength,
                                            GZIP=self.GZIP,
                                            CHUNKED=self. CHUNKED,
                                            randomized = self.randomized,
                                            DATAONLY = DATAONLY)
        else:
            #STEP 3 Client Send File
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Upload_File(FILE = FILE,
                                          rlength = self.rlength,
                                               randomized = self.randomized,
                                          DATAONLY = DATAONLY)
            

            #STEP 4 SERVER RESPONCE HEADERS
            self.SendResponseHeaders(Flow = 'HTTP')

        #STEP 5 Finish up flow
        if test=='2 fin':
            self.Flows['HTTP'].Fin_Flow()
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
            self.Flows['HTTP'].Fin_Flow()
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
        elif test == '1 reset':
            self.Flows['HTTP'].reset_Flow()
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
        elif test == '2 reset':
            self.Flows['HTTP'].reset_Flow()
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
            self.Flows['HTTP'].reset_Flow()
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
        else:
            print 'regular fin flow'
            print 'packets till now', len(self.Flows['HTTP'].packets)
            self.Flows['HTTP'].Fin_Flow()
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
        return self.Packets

        
    def HTTP_PIPELINE_TEST(self):
        assert self.METHOD == 'GET', 'only GET is supported for HTTP pipelining'
        self.Packets = []
        #step 1 Sync
        self.Setup_Flow(Flow='HTTP')
        
        #Step 2 Client HTTP request headers
        for FILE in self.FILES:
            self.SendRequestHeaders(Flow = 'HTTP')

        #now send responces
        for FILE in self.FILES:
            #STEP 3 SERVER RESONSE HEADERS
            self.SendResponseHeaders(Flow = 'HTTP',
                                     contentLength = len(open(FILE).read()))

            #STEP 4 SERVER SEND file
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Download_File(FILE = FILE,
                                             rlength = self.rlength,
                                            GZIP=self.GZIP,
                                            CHUNKED=self.CHUNKED,
                                            randomized = self.randomized)
            
        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['HTTP'].packets
        #clear out old packets not added to main packet stream
        self.Flows['HTTP'].packets = []
        return self.Packets
        
    def DownloadFile_Test(self,
                          FILE):
        #step 1 Sync
        self.Setup_Flow(Flow='HTTP')
                    
        #step 2 Send Client Request Headers
        self.SendRequestHeaders(Flow = 'HTTP')
        
       
        #STEP 3 SERVER RESONSE HEADERS
        self.SendResponseHeaders(Flow = 'HTTP')

           

            
        #STEP 4 SERVER SEND file
        if 'error' in self.ServerResponce.lower():
            pass
        else:
            self.Flows['HTTP'].Download_File(FILE = FILE,
                                         rlength = self.rlength,
                                         GZIP=self.GZIP,
                                         CHUNKED=self. CHUNKED,
                                         randomized = self.randomized)

        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['HTTP'].packets
        #clear out old packets not added to main packet stream
        self.Flows['HTTP'].packets = []
        
    def UploadFile_Test(self,
                        FILE):
        #step 1 Sync
        self.Setup_Flow(Flow='HTTP')

        self.GetLength(CalcLengthof=FILE)
        self.GetMime(FILE=FILE)
        #step 2 Send Client Request Headers
        self.SendRequestHeaders(Flow = 'HTTP')

        #STEP 3 Client Send File
        if 'error' in self.ServerResponce.lower():
            pass
        else:
            self.Flows['HTTP'].Upload_File(FILE = FILE,
                                       rlength = self.rlength,
                                               randomized = self.randomized)
            

        #STEP 4 SERVER RESPONCE HEADERS
        self.SendResponseHeaders(Flow = 'HTTP')

        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['HTTP'].packets
        #clear out old packets not added to main packet stream
        self.Flows['HTTP'].packets = []
    def UploadFile_DownloadFile_Test(self,
                                     downlaodFile,
                                     UploadFile,
                                     ):
        #step 1 Sync
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]
        self.GetLength(CalcLengthof=downlaodFile)
        self.GetMime(FILE=downlaodFile)
        #step 2 Send Client Request Headers
        self.SendRequestHeaders(Flow = 'HTTP')
        
       
        

        #STEP 3 Client Send File
        if 'error' in self.ServerResponce.lower():
            pass
        else:
            self.Flows['HTTP'].Upload_File(FILE = UploadFile,
                                      rlength = self.rlength,
                                               randomized = self.randomized)
            

        #STEP 4 SERVER RESPONCE HEADERS

        self.SendResponseHeaders(Flow = 'HTTP')

        #STEP 5 SERVER SEND file
        if 'error' in self.ServerResponce.lower():
            pass
        else:
            self.Flows['HTTP'].Download_File(FILE = downlaodFile,
                                     rlength = self.rlength,
                                     GZIP=self.GZIP,
                                     CHUNKED=self. CHUNKED,
                                     randomized = self.randomized)
        

        #STEP 6 FIN
        self.Flows['HTTP'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['HTTP'].packets
        #clear out old packets not added to main packet stream
        self.Flows['HTTP'].packets = []
        
        
        
    def HTTP_MULTI_TEST(self):
        self.Packets = []
        #step 1 Sync
        self.Setup_Flow(Flow='HTTP',
                   )
        for FILE in self.FILES:
            #Step 2 Client HTTP request headers
            self.SendRequestHeaders(Flow = 'HTTP')

            self.GetLength(CalcLengthof=FILE)
            self.GetMime(FILE=FILE)
            
            if self.METHOD == 'GET':
                #STEP 3 SERVER RESONSE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP',
                                         contentLength=len(open(FILE).read()))

                
                #STEP 4 SERVER SEND file
                if 'error' in self.ServerResponce.lower():
                    pass
                else:
                    self.Flows['HTTP'].Download_File(FILE = FILE,
                                                    rlength = self.rlength,
                                                    GZIP=self.GZIP,
                                                    CHUNKED=self.CHUNKED,
                                                    randomized = self.randomized)
            else:
                #STEP 3 Client Send File
                if 'error' in self.ServerResponce.lower():
                    pass
                else:
                    self.Flows['HTTP'].Upload_File(FILE = FILE,
                                              rlength = self.rlength,
                                               randomized = self.randomized)
                

                #STEP 4 SERVER RESPONCE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP')
                


        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['HTTP'].packets
        #clear out old packets not added to main packet stream
        self.Flows['HTTP'].packets = []
        return self.Packets
    def HTTP_MULTIPLEFLOWS_SAMEPORT(self,
                                    Times=5):
        FILE = self.FILES[0]
        self.GetLength(CalcLengthof=FILE)
        self.GetMime(FILE=FILE)

        #step 1 Sync
        self.Setup_Flow(Flow='HTTP')

        contentlength = len(open(FILE, 'rb').read())
        for i in range(Times):
            #step 1 Sync
            self.Setup_Flow(Flow='HTTP')
            #Step 2 Client HTTP request headers
            self.SendRequestHeaders(Flow = 'HTTP')
           
            if self.METHOD == 'GET':
                #STEP 3 SERVER RESONSE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP')

                
                #STEP 4 SERVER SEND file
                if 'error' in self.ServerResponce.lower():
                    pass
                else:
                    self.Flows['HTTP'].Download_File(FILE = FILE,
                                                rlength = self.rlength,
                                                GZIP=self.GZIP,
                                                CHUNKED=self.CHUNKED,
                                                randomized = self.randomized)
            else:
                #STEP 3 Client Send File
                if 'error' in self.ServerResponce.lower():
                    pass
                else:
                    self.Flows['HTTP'].Upload_File(FILE = FILE,
                                                  rlength = self.rlength,
                                               randomized = self.randomized)
                

                #STEP 4 SERVER RESPONCE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP')

        
            #STEP 5 FIN
            self.Flows['HTTP'].Fin_Flow()
            
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['HTTP'].packets
            #clear out old packets not added to main packet stream
            self.Flows['HTTP'].packets = []
            self.InitClientSeq = self.Flows['HTTP'].TCP.seq
            self.InitServerSeq = self.Flows['HTTP'].TCP.ack

            
    def HTTP_CONTINUOUS_SESSION_TEST(self):
        FILE = self.FILES[0]
        self.GetLength(CalcLengthof=FILE)
        self.GetMime(FILE=FILE)

        #setup socket for fast sending

        #step 1 Sync
        self.Setup_Flow(Flow='HTTP',
                   )

        print 'speed', self.Verbose
        #send sync packets
        if self.Verbose == None:
            sendp(self.Flows['HTTP'].packets, iface = self.INTF, verbose=0)
        else:
            sendpfast(self.Flows['HTTP'].packets,iface=self.INTF,pps=self.Verbose)
            #sendp(self.Flows['HTTP'].packets, iface = self.INTF, verbose = self.Verbose)
        
        self.Flows['HTTP'].packets = []
        contentlength = len(open(FILE, 'rb').read())
        for i in range(self.TIME):
            #Step 2 Client HTTP request headers
            self.SendRequestHeaders(Flow = 'HTTP')
           
            if self.METHOD == 'GET':
                #STEP 3 SERVER RESONSE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP')

                
                #STEP 4 SERVER SEND file
                if 'error' in self.ServerResponce.lower():
                    pass
                else:
                    self.Flows['HTTP'].Download_File(FILE = FILE,
                                                    rlength = self.rlength,
                                                    GZIP=self.GZIP,
                                                    CHUNKED=self.CHUNKED,
                                                    randomized = self.randomized)
            else:
                #STEP 3 Client Send File
                if 'error' in self.ServerResponce.lower():
                    pass
                else:
                    self.Flows['HTTP'].Upload_File(FILE = FILE,
                                              rlength = self.rlength,
                                               randomized = self.randomized)
                

                #STEP 4 SERVER RESPONCE HEADERS
                self.SendResponseHeaders(Flow = 'HTTP')

            #send DATA packets
            if self.Verbose == None:
                sendp(self.Flows['HTTP'].packets, iface = self.INTF, verbose=0)
            else:
                sendpfast(self.Flows['HTTP'].packets,iface=self.INTF,pps=self.Verbose)
                #sendp(self.Flows['HTTP'].packets, iface = self.INTF, verbose = self.Verbose)
            self.Flows['HTTP'].packets = []

        
        #STEP 5 FIN
        self.Flows['HTTP'].Fin_Flow()

        #send FIN packets
        if self.Verbose == None:
            sendp(self.Flows['HTTP'].packets, iface = self.INTF, verbose=0)
        else:
            sendpfast(self.Flows['HTTP'].packets,iface=self.INTF,pps=self.Verbose)
            #sendp(self.Flows['HTTP'].packets, iface = self.INTF, verbose = self.Verbose)
        self.Flows['HTTP'].packets = []

    def HTTP_TEST_NO_FIN(self,
                      wait=0,
                      DATAONLY=0):


        # step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]

        # step 2 Send Client Request Headers
        # dont scrample the request headers
        self.SendRequestHeaders(Flow='HTTP')

        if self.METHOD == 'GET':
            # STEP 3 SERVER RESONSE HEADERS
            # dont scrample the response headers
            self.SendResponseHeaders(Flow='HTTP')

            # STEP 4 SERVER SEND file

            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Download_File(FILE=FILE,
                                                 rlength=self.rlength,
                                                 GZIP=self.GZIP,
                                                 CHUNKED=self.CHUNKED,
                                                 randomized=self.randomized,
                                                 DATAONLY=DATAONLY)
        else:
            # STEP 3 Client Send File
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Upload_File(FILE=FILE,
                                               rlength=self.rlength,
                                               randomized=self.randomized,
                                               DATAONLY=DATAONLY)

            # STEP 4 SERVER RESPONCE HEADERS
            self.SendResponseHeaders(Flow='HTTP')

        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []
        return self.Packets


    def HTTP_RESPONCEFIRST_TEST(self):
        #step 1 Sync
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []

        
        FILE = self.FILES[0]
        self.GetLength(CalcLengthof=FILE)
        self.GetMime(FILE=FILE)
        
        if self.METHOD == 'GET':
            #STEP 3 SERVER RESONSE HEADERS
            #print 'sending responce'
            self.SendResponseHeaders(Flow = 'HTTP')
            
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []

            
            #STEP 4 SERVER SEND file
            #print 'downloading file'
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Download_File(FILE = FILE,
                                            rlength = self.rlength,
                                            GZIP=self.GZIP,
                                            CHUNKED=self. CHUNKED,
                                            randomized = self.randomized)

            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []

            #step 2 Send Client Request Headers
            #print 'sending request'
            self.SendRequestHeaders(Flow = 'HTTP')

            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
        
        else:
            
            #STEP 3 Client Send File
            #print 'uploading file'
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Upload_File(FILE = FILE,
                                          rlength = self.rlength,
                                               randomized = self.randomized)
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
            

            #STEP 4 SERVER RESPONCE HEADERS
            #print 'sending response'
            self.SendResponseHeaders(Flow = 'HTTP')

            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
            
            #step 2 Send Client Request Headers
            #print 'sending request'
            self.SendRequestHeaders(Flow = 'HTTP')
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []

        #STEP 5 FIN
        #print 'sending fin'
        self.Flows['HTTP'].Fin_Flow()
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []
        return self.Packets
        
    

        
    def HTTP_MULTIREQUEST_RESPONSE(self,
                                     NumberofRequests = 2,
                                     NumberofResponses = 1,
                                     ):
        #step 1 Sync
        #print 'sending sync'
        self.Packets = []
        self.Setup_Flow(Flow='HTTP')
        FILE = self.FILES[0]
        self.GetLength(CalcLengthof=FILE)
        self.GetMime(FILE=FILE)
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []

        
        #step 2 Send Client Request Headers
        for i in range(NumberofRequests):
            #print 'sending client request'
            self.SendRequestHeaders(Flow = 'HTTP')
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []

        
        
    
        if self.METHOD == 'GET':
            #STEP 3 SERVER RESONSE HEADERS
            for i in range(NumberofResponses):
                #print 'sending server response'
                self.SendResponseHeaders(Flow = 'HTTP')
                self.Packets += self.Flows['HTTP'].packets
                self.Flows['HTTP'].packets = []
            


            
            #STEP 4 SERVER SEND file
            #print 'downloading file'
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Download_File(FILE = FILE,
                                            rlength = self.rlength,
                                            GZIP=self.GZIP,
                                            CHUNKED=self. CHUNKED,
                                            randomized = self.randomized)
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
        else:
            #STEP 3 Client Send File
            #print 'uploading file'
            if 'error' in self.ServerResponce.lower():
                pass
            else:
                self.Flows['HTTP'].Upload_File(FILE = FILE,
                                          rlength = self.rlength,
                                               randomized = self.randomized)
            self.Packets += self.Flows['HTTP'].packets
            self.Flows['HTTP'].packets = []
            #STEP 4 SERVER RESPONCE HEADERS
            
            for i in range(NumberofResponses):
                #print 'sending server response'
                self.SendResponseHeaders(Flow = 'HTTP')
                self.Packets += self.Flows['HTTP'].packets
                self.Flows['HTTP'].packets = []

        #STEP 5 FIN
        #print 'sending fin'
        self.Flows['HTTP'].Fin_Flow()
        self.Packets += self.Flows['HTTP'].packets
        self.Flows['HTTP'].packets = []

        return self.Packets
        
        
if __name__ == '__main__':
    self = HTTP_Support()
    self.SetVariables(METHOD = 'GET',
                          UserAgent = 'curl/7.35.0',
                          dmac = '11:22:33:44:55:66',
                          smac = '22:33:44:55:66:77',
                          src = '1.1.3.5',
                          dst = '2.2.3.6',
                          sport = 12345,
                          dport = 80,
                          INTF = 'wlan0',
                          FILES = ['/mnt/files/Malicious_DOC.doc'],
                          InitClientSeq=1,
                          InitServerSeq=1,
                          HTTPVERSION= 'HTTP/1.1',
                          ServerResponce = 'HTTP/1.1 200 OK',
                          ServerName = 'Nathans_HTTP_SERVER/0.1 Python/2.7.6',
                          GZIP = False,
                          CHUNKED = 5,
                          rlength = 1500,
                          TIME = 60, #60 seconds
                          Verbose = None,
                          HOST = 'testing.com',
                          URLBASE = '/bababa',
                          vlanTag=None,
                          #DISPSITION =[{'name':'file'}, {'filename':'post.file'}],
                          )

    #PACKETS = self.HTTP_TEST(test= "1 reset")
    #wrpcap('/home/nathanhoisington/1reset.pcap', PACKETS)
    #PACKETS = self.HTTP_TEST(test= "2 reset")
    #wrpcap('/home/nathanhoisington/2reset.pcap', PACKETS)
    #PACKETS = self.HTTP_TEST(test= "2 fin")
    #wrpcap('/home/nathanhoisington/2fin.pcap', PACKETS)
    PACKETS = self.HTTP_TEST()
    print 'len packets', PACKETS
    wrpcap('/home/nathan/http_chunked100.pcap', PACKETS)
    #NSS testing pcaps
    '''
    NSSLIST = [ '/data/nssfiles/025acb6c872cb553793ad8df772d2dcd2cfb29ba882a9b08cbca9e0f6b73cce8',
            '/data/nssfiles/1c69db63daa1b0e128284a5f4dc94813800f349a8605e161a1b186d848322cd7',
            '/data/nssfiles/2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad',
            '/data/nssfiles/31b43e143f1992a102728a7c5145553211574ae0745e6e768b9d512ddf768df0',
            '/data/nssfiles/41c28dbf4819c306b056a3e2b04b0e03bab6b9d11c63b6bebdf94e1956eab1fc',
            '/data/nssfiles/5328587008e827ec1444e2fc2be7cbdd95974b3dad0d7e1c90a7d5f7d69ac024',
            '/data/nssfiles/66c749bd72e2ba889ce3643f4956939fe870cba7e69cdfffcc2d06664023cbe1_d',
            '/data/nssfiles/6dbe083f14496a8c7f604bade527f3b619fc51acbcf5849f970e271bf2671b2e',
            '/data/nssfiles/6ee86345c03c119511de2c81c707f2c69bb243b28a770c31d201e6d74b8c183c',
            '/data/nssfiles/84d8813f1b6e1f33f316c5de46d7764f1c9ba8e4e428321ed70048f9c5c2558c_d',
            '/data/nssfiles/a63af8b74150f0314bd535b4d24c67963bbfcf0ca59a58765c14e83d8b4c6a5d',
            '/data/nssfiles/about[1].exe',
            '/data/nssfiles/ae5e549d17f01724e820b3417197594eef5b2b593c400e45d28219b2b302a8fc',
            '/data/nssfiles/ap2.php',
            '/data/nssfiles/atqelu.exe',
            '/data/nssfiles/awree.exe',
            '/data/nssfiles/azodta.exe',
            '/data/nssfiles/b599acd8492e72b0b435ce33d1c60d1df3f7efd9d27edbdeb931a22b212ee055_d',
            '/data/nssfiles/calc[1].exe',
            '/data/nssfiles/d9a6ed27d30e09a2dbd39ea0ba7e03c33cdfc1948bae31c679586d1eafdc63ef',
            '/data/nssfiles/df73b82835d47d3ceeeb90d0c9d64f74cc44410edde2f3f608eeb9d11e88a841_d',
            '/data/nssfiles/install_0_msi.exe',
            '/data/nssfiles/operation_alert_login.php',
            '/data/nssfiles/updateflashplayer.exe',
           '/data/nssfiles/wgsdgsdgdsgsd.exe',
                ]

    for FILE in NSSLIST:
        self.SetVariables(METHOD = 'GET',
                          UserAgent = 'curl/7.35.0',
                          dmac = '11:22:33:44:55:66',
                          smac = '22:33:44:55:66:77',
                          src = '1.1.1.1',
                          dst = '2.2.2.2',
                          sport = 1234,
                          dport = 80,
                          INTF = 'wlan0',
                          FILES = [FILE],
                          InitClientSeq=1,
                          InitServerSeq=1,
                          HTTPVERSION= 'HTTP/1.1',
                          ServerResponce = 'HTTP/1.1 200 OK',
                          ServerName = 'Nathans_HTTP_SERVER/0.1 Python/2.7.6',
                          GZIP = False,
                          CHUNKED = False,
                          rlength = 1500,
                          TIME = 60, #60 seconds
                          Verbose = None,
                          HOST = 'testing.com',
                          URLBASE = '/bababa',
                          #DISPSITION =[{'name':'file'}, {'filename':'post.file'}],
                          )
        PACKETS = self.HTTP_TEST()
        wrpcap('/data/nsspcaps/%s_GET.pcap' %os.path.basename(FILE), PACKETS)
     '''
    ###CUSTOM RESPONCE
    '''
    PACKETS = self.HTTP_custom_response(serverresponse = ['server responce'])
    wrpcap('HTTP_%s_customresponse.pcap' %Method, PACKETS)
    '''
    ###SYNC ATTACK TEST
    '''
    PACKETS = self.HTTP_SYNC_ATTACK(requestattempts=2)
    wrpcap('HTTP_%s_SYNCATTACK.pcap' %Method, PACKETS)
    '''
        

    ###UPLOAD_DOWNLOAD TEST
    '''
    MALICIOUS_FILE = self.FILES[0]
    BENIGN_FILE = self.FILES[1]
    if self.METHOD == 'GET':
        self.UploadFile_Test(MALICIOUS_FILE)
        #sendp(self.Packets, iface = self.INTF)
        wrpcap('%s_UPLOAD.pcap' %self.METHOD,self.Packets)
        self.Packets = []
    else:
        self.DownloadFile_Test(MALICIOUS_FILE)
        #sendp(self.Packets, iface = self.INTF)
        wrpcap('%s_DOWNLOAD.pcap' %self.METHOD,self.Packets)
        self.Packets = []


    self.Packets = []

    self.UploadFile_DownloadFile_Test(MALICIOUS_FILE,
                                      BENIGN_FILE)
    #sendp(self.Packets, iface = self.INTF)
    wrpcap('%s_DOWNLOADMALICIOUS_UPLOADBENIGN.pcap' %self.METHOD,self.Packets)
    self.Packets = []

    self.UploadFile_DownloadFile_Test(BENIGN_FILE,
                                      MALICIOUS_FILE,
                                      )
    #sendp(self.Packets, iface = self.INTF)
    wrpcap('%s_DOWNLOADBENIGN_UPLOADMALICIOUS.pcap' %self.METHOD,self.Packets)

    self.Packets = []
    '''


    ### FOR SWAPPING TEST###
    '''
    S = 2
    SA = 18
    FA = 17
    #create with client sync missing +5 more clients
    PACKETS = self.HTTP_TEST()
    i = 0
    for packet in PACKETS:
        if i == 0 and packet[TCP].flags == S:
            print 'found client S'
            PACKETS.remove(packet)
            i += 1
        if i > 0:
            if packet[IP].src == self.src:
                #print 'removing', packet.show()
                try:
                    PACKETS.remove(packet)
                except ValueError:
                    pass
                i += 1
            if i == 5:
                wrpcap('HTTP_%s_missingClientSyncand5moreClient.pcap' %Method, PACKETS)
                break

    #create with server sync missing + 5 more server
    PACKETS = self.HTTP_TEST()
    i = 0
    for packet in PACKETS:
        if i == 0 and packet[TCP].flags == SA:
            print 'found server SA'
            PACKETS.remove(packet)
            i += 1
        if i > 0:
            if packet[IP].src == self.dst:
                #print 'removing', packet.show()
                try:
                    PACKETS.remove(packet)
                except ValueError:
                    pass
                i += 1
            if i == 5:
                wrpcap('HTTP_%s_missingServerSyncand5moreServer.pcap' %Method, PACKETS)
                break


    #create server fin before client fin
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == FA and packet[IP].src == self.dst:
            print 'makeing server fin after client ack'
            i = PACKETS.index(packet)
            L = PACKETS[i-1:i+1]
            print 'setting ', L, 'to', L[::-1]
            PACKETS[i-1:i+1] = L[::-1]
            wrpcap('HTTP_%s_ServerFINbeforeClientFIN.pcap' %Method, PACKETS)
            break


    #create server sync before client syn
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == SA:
            print 'makeing server sync after client ack'
            i = PACKETS.index(packet)
            L = PACKETS[i-1:i+1]
            print 'setting ', L, 'to', L[::-1]
            PACKETS[i-1:i+1] = L[::-1]
            #PACKETS[i-1:i+1] = PACKETS[i:i-1:-1]
            wrpcap('HTTP_%s_ServerSYNbeforeClientSYN.pcap' %Method, PACKETS)
            break


    #create with client sync missing
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == S:
            print 'found client S'
            PACKETS.remove(packet)
            wrpcap('HTTP_%s_missingClientSync.pcap' %Method, PACKETS)
            break


    #create with server sync missing
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == SA:
            print 'found server SA'
            PACKETS.remove(packet)
            wrpcap('HTTP_%s_missingServerSync.pcap' %Method, PACKETS)
            break


    #create with client fin missing
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == FA and packet[IP].src == self.src:
            print 'found client FA'
            PACKETS.remove(packet)
            wrpcap('HTTP_%s_missingClientFin.pcap' %Method, PACKETS)
            break

    #create with server fin missing
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == FA and packet[IP].src == self.dst:
            print 'found Server FA'
            PACKETS.remove(packet)
            wrpcap('HTTP_%s_missingServerFin.pcap' %Method, PACKETS)
            break

    #create server sync after client ack
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == SA:
            print 'makeing server sync after client ack'
            i = PACKETS.index(packet)
            PACKETS[i:i+2] = PACKETS[i+1:i-2:-1]
            wrpcap('HTTP_%s_ServerSYNafterClientACK.pcap' %Method, PACKETS)
            break

    #create server sync before client ack
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == SA:
            print 'makeing server sync after client ack'
            i = PACKETS.index(packet)
            PACKETS[i-1:i+2] = PACKETS[i:i-1:-1]
            wrpcap('HTTP_%s_ServerSYNbeforeClientSYN.pcap' %Method, PACKETS)
            break


    #create server fin after client ack
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == FA and packet[IP].src == self.dst:
            print 'makeing server fin after client ack'
            i = PACKETS.index(packet)
            PACKETS[i:i+2] = PACKETS[i+1:i-2:-1]
            wrpcap('HTTP_%s_ServerFINafterClientACK.pcap' %Method, PACKETS)
            break

    #create server fin before client ack
    PACKETS = self.HTTP_TEST()
    for packet in PACKETS:
        if packet[TCP].flags == FA and packet[IP].src == self.dst:
            print 'makeing server fin after client ack'
            i = PACKETS.index(packet)
            PACKETS[i-1:i+2] = PACKETS[i:i-1:-1]
            wrpcap('HTTP_%s_ServerFINbeforeClientFIN.pcap' %Method, PACKETS)
            break
    '''
