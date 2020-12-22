from TCP_flow_control import *
from Scapy_Control import *

class FTP_Support():
    def __init__(self):
        self.Packets = []
        self.Flows={}
    def SetVariables(self,
                     METHOD = 'GET',
                     dmac = '22:22:22:22:22:22',
                     smac = '11:11:11:11:11:11',
                     TYPE= 'ipv4',
                     src = '1.1.1.1',
                     dst = '2.2.2.2',
                     srcv6 = None,
                     dstv6 = None,
                     csport = 12345,
                     cdport = 21,
                     ddport = 43210,
                     dsport = 43211,
                     ftpuser = 'root',
                     ftppassword = 'password',
                     ServerDir = '/',
                     CWD = '/',
                     Passive = False,
                     FTPTYPE = 'I',  #???
                     FILES = None,
                     InitClientSeq = 1,
                     InitServerSeq = 1,
                     rlength = 1500,
                     INTF = 'wlan0',
                     SEGMENTS = 1,
                     vlanTag=None):
        self.METHOD = METHOD
        self.dmac = dmac
        self.smac = smac
        self.TYPE = TYPE
        self.src = src
        self.dst = dst
        self.srcv6 = srcv6 
        self.dstv6 = dstv6 
        self.csport = csport
        self.cdport = cdport
        self.dsport = dsport
        self.ddport = ddport
        self.INTF = INTF
        self.FILES = FILES
        self.ServerDir = ServerDir
        self.CWD = CWD
        self.Passive = Passive
        self.vlanTag = vlanTag
        FTPTYPE = 'TYPE %s' %FTPTYPE
        self.FTPTYPE = FTPTYPE
        if FTPTYPE == 'TYPE I':
            self.ServerResponseType = 'Binary'
        elif FTPTYPE == 'TYPE E':
            self.ServerResponseType = 'EDBDIC'
        elif FTPTYPE == 'TYPE A':
            self.ServerResponseType = 'ASCII'
        elif FTPTYPE == 'TYPE L':
            self.ServerResponseType = 'Local format'
        else:
            raise Exception('%s is and invalid ftp type' %FTPTYPE)
        self.InitClientSeq=InitClientSeq
        self.InitServerSeq=InitServerSeq
        self.ftpuser = ftpuser
        self.ftppassword = ftppassword
        self.rlength = rlength
        self.SEGMENTS = SEGMENTS

        if FTPTYPE == 'TYPE A':
            #print 'acii type checking'
            for File in FILES:
                #print 'checking if %s is ascii' %File
                assert IsAsciiFile(File) == True, 'File is not in an ASCII file. text files supported like: txt, htm, html, css, asp, vbs, js'
                
            
            
    
    def Setup_Flow(self,
                   FlowName='FTP_TRAFFIC', #'FTP_COMMAND' #'FTP_DATA'
                   dport = None,
                   sport = None):
        assert dport != None, 'must devine a dport'
        assert sport != None, 'must define an sport'

        #print 'setting flow name', FlowName
        #print 'sync dport', dport, 'with sport', sport
        
        FlowObject = TCP_flow_control()
        FlowObject.Sync_Flow(dmac = self.dmac,
                               smac = self.smac,
                               TYPE= self.TYPE,
                               src = self.src,
                               dst = self.dst,
                             srcv6 = self.srcv6,
                             dstv6 = self.dstv6,
                               dport = dport,
                               sport = sport,
                               InitClientSeq = self.InitClientSeq,
                               InitServerSeq = self.InitServerSeq,
                               vlanTag=self.vlanTag)
        self.Flows[FlowName] = FlowObject

    
    def FTP_INIT(self,
                 FlowName = None,
                 dport = None,
                 sport = None,
                 ):
        assert FlowName != None, 'must define FlowName'
        self.Setup_Flow(FlowName=FlowName,
                        dport = dport,
                        sport = sport,
                        )
        
        #Step 1 server INITIATE
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '220 (vsFTPd 3.0.2)\r\n')
        self.Flows[FlowName].ConStruct_Packet_Without_Data(fromSrc = True)

        #Step 2 Client Connect
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'USER %s\r\n' %self.ftpuser)
        
        
        self.Flows[FlowName].ConStruct_Packet_Without_Data(fromSrc = False)


        #Server Ask for password
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '331 Please specify the password.\r\n')
        

        #client Responce with password
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'PASS %s\r\n' %self.ftppassword)
        

        #Server Responce with successful
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '230 Login successful.\r\n')

        #Client Responce with PWD
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'PWD\r\n')
      

        #Server Responce with homedir
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '257 %s\r\n' %self.ServerDir)
        #Client change working directory
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'CWD %s\r\n' %self.CWD)
        #Server Responce with success
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '250 Directory successfully changed.\r\n')
    def FTP_LOGIN(self,
                  FILE,
                  FlowName,
                  ):
        assert os.path.exists(FILE) == True, '%s does not exist' %FILE

        
        self.FTP_INIT(FlowName = FlowName,
                      dport = self.cdport,
                      sport = self.csport,
                      )
        
    
        #Step 3 setup passive/active port
        if self.Passive == True:
            #Client makes passive request
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'PASV\r\n')

            o1, o2, o3, o4  = self.dst.split('.')
            d1 = self.ddport/256
            d2 = self.ddport - (256*d1)

            #client set port
            data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= data)


            '''
            #Client makes passive request
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'EPSV\r\n')
        
            #Server Responce with entering passive mode
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '229 Entering Extended Passive Mode (|||%s|).\r\n' %str(ddport))

            ###ON PASSIVE CLIENT REQUESTS ARE MADE AFTER syncing DATA PORTS
            '''
        else:
            '''
            #client makes active request
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'EPRT |1|%s|%s|\r\n' %(dst,str(ddport)))
        
            #server set active mode
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '200 EP[13]RT command successful. Consider using EPSV.\r\n')
            '''
            #set client Type
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= '%s\r\n' %self.FTPTYPE)

            #server response switch to binary
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data='200 Switching to %s mode.\r\n' %self.ServerResponseType)
            

            if self.METHOD == 'GET':
                #client request filesize

                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'SIZE %s\r\n' %os.path.basename(FILE))


                #Server responce filesize
                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data='213 %i\r\n' %len(open(FILE,'rb').read()))
            
                '''
                #server ask date
                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'MDTM %s\r\n' %os.path.basename(FILE))


                #Client responce ramd
                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data='213 %s\r\n' %str('20150414130509'))
                '''

            #port set for client to connect to server 
            o1, o2, o3, o4  = self.src.split('.')
            d1 = self.dsport/256
            d2 = self.dsport - (256*d1)

            #client set port
            data = 'PORT %s,%s,%s,%s,%i,%i\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data= data)

            #server acknowledge
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '200 PORT command successful. Consider using PASV.\r\n',
                                                                 )
                
            #client request
            if self.METHOD == 'APPEND':
                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='APPE %s\r\n' %os.path.basename(FILE),
                                                                    Flags = 'PA')
            if self.METHOD == 'GET':
                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='RETR %s\r\n' %os.path.basename(FILE),
                                                                    Flags = 'PA')
            if self.METHOD == 'PUT':
                self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='STOR %s\r\n' %os.path.basename(FILE),
                                                                    Flags = 'PA')

            
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows[FlowName].packets
        #clear out old packets not added to main packet stream
        self.Flows[FlowName].packets = []
    def FTP_SEGMENTATION_TEST(self,
                              ):
        FILE = self.FILES[0]
        self.Packets = []
        #step 1 FTP login
        #print 'attempt command dp', self.cdport, 'sp', self.csport
        self.FTP_INIT(FlowName = 'CommandFlow0',
                      dport = self.cdport,
                      sport = self.csport,
                      )
        #BINARY MODE
        #set client Type
        self.Flows['CommandFlow0'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= '%s\r\n' %self.FTPTYPE)
        #server response switch to binary
        self.Flows['CommandFlow0'].ConStruct_Packet_With_Data(fromSrc = False,
                                                             data='200 Switching to %s mode.\r\n' %self.ServerResponseType)

        #GET SIZE
        #client request filesize
        self.Flows['CommandFlow0'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'SIZE %s\r\n' %os.path.abspath(FILE))


        #Server responce filesize
        self.Flows['CommandFlow0'].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data='213 %i\r\n' %len(open(FILE,'rb').read()))

        self.Packets += self.Flows['CommandFlow0'].packets
        #clear out old packets not added to main packet stream
        self.Flows['CommandFlow0'].packets = []

        #lets SYNC the rest of the Threads
        for i in range(1, self.SEGMENTS):
            #init a new session
            flowName = 'CommandFlow%i' %i
            self.FTP_INIT(FlowName = flowName,
                          dport = self.cdport,
                          sport = self.csport+i,)
        
            self.Packets += self.Flows['CommandFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['CommandFlow%i' %i].packets = []

        
            
        #lets Split File into smaller sizes
        FILESIZE = len(open(FILE,'rb').read())
        SplitSize = (FILESIZE/int(self.SEGMENTS)) +1
        #Client makes passive request
            

        #lets set PASV TRAFFIC
        for i in range(self.SEGMENTS):
            start= i*SplitSize
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'PASV\r\n')

            o1, o2, o3, o4  = self.dst.split('.')
            d1 = (self.ddport + i)/256
            d2 = (self.ddport + i) - (256*d1)

            #client set port
            
            data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= data)
            self.Packets += self.Flows['CommandFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['CommandFlow%i' %i].packets = []

            flowName = 'DataFlow%i' %i
            self.Setup_Flow(FlowName=flowName,
                            dport = self.ddport +i,
                            sport = self.dsport +i ,)
            self.Packets += self.Flows['DataFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['DataFlow%i' %i].packets = []
            
            if start == 0: #initial retr call
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='RETR %s\r\n' %os.path.abspath(FILE),
                                                                    Flags = 'PA')
            else:
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='REST %i\r\n' %start,
                                                                    Flags = 'PA')
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                                    data='350 Restart position accepted (%i).\r\n' %start,
                                                                    Flags = 'PA')
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='RETR %s\r\n' %os.path.abspath(FILE),
                                                                    Flags = 'PA')
            ##this next line may be unnessesary
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= '%s\r\n' %self.FTPTYPE)
            ###DONe possible unnessassary line
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '150 Opening %s mode data connection for %s (%i bytes).\r\n' %(self.ServerResponseType,
                                                                                                                                          os.path.abspath(FILE),
                                                                                                                                          len(open(FILE,'rb').read())))
            self.Packets += self.Flows['CommandFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['CommandFlow%i' %i].packets = []
            


        #lets Download Segments now
        
        for i in reversed(range(self.SEGMENTS)): #run in reverse order
            start= i*SplitSize
            #retv points
            self.Flows['DataFlow%i' %i].Download_Segment(FILE = FILE, #
                                                         StartRead = start, #place to read file
                                                         BytesToRead = SplitSize, #place to finish
                                                         rlength = 1500,
                                                         )
            
            self.Packets += self.Flows['DataFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['DataFlow%i' %i].packets = []
            
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data= '\xff\xf4\xff',
                                                                      Flags= 'PA')
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data= '\xf2',
                                                                      Flags = 'PAU')
            self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data= 'ABOR\r\n',
                                                                      Flags = 'PA')
            #if i == -1:#there is no negative 1
            if i == 0:
                #do nothing on first transfer
                pass
                #self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                #                                                 data= '426 Failure writing network stream.\r\n',
                #                                                 )
                
            else:
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '226 Transfer complete.\r\n',
                                                                 )
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data= '225 No trasfer to ABOR.\r\n',
                                                                     )
            
            

            self.Packets += self.Flows['CommandFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['CommandFlow%i' %i].packets = []            
            
        #lets Fin Data Flow
        for i in reversed(range(self.SEGMENTS)):
            self.Flows['DataFlow%i' %i].Fin_Flow()
            self.Packets += self.Flows['DataFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['DataFlow%i' %i].packets = []
        #lets Fin Command Flow

        #client quit
        for i in reversed(range(self.SEGMENTS)):
            if i == 0:  #dont say bye
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '426 Failure writing network stream.\r\n',
                                                                 )
            else:
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'QUIT\r\n')

                #server say goodbye
                self.Flows['CommandFlow%i' %i].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '221 Goodbye.\r\n')
            #FIN
            self.Flows['CommandFlow%i' %i].Fin_Flow()
            self.Packets += self.Flows['CommandFlow%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['CommandFlow%i' %i].packets = []
        return self.Packets
                              
    def FTP_TEST(self,
                 ):
        FILE = self.FILES[0]
        self.Packets = []
        #step 1 FTP login
        self.FTP_LOGIN(FILE,'FTP_COMMAND')
        
    
       
        #Step2 Sync FTP DATA
        self.Setup_Flow(FlowName='FTP_DATA',
                        dport = self.ddport,
                        sport = self.dsport,)

        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_DATA'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_DATA'].packets = []


        #switch back to command ports
        if self.Passive == False:
            #Server ready to send data
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='150 Ok to send data.\r\n')
        else:
            #client acknowledge
            self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)
            #client send type
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='%s\r\n' %self.FTPTYPE)

            #server response switch to binary
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='200 Switching to %s mode.\r\n' %self.ServerResponseType)

            #Acknowledgement on client connection
            self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)

            if self.METHOD == 'GET':
                #client request filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='SIZE %s\r\n' %os.path.basename(FILE))

                #Server responce filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='213 %i\r\n' %len(open(FILE,'rb').read()))
                #Client request file retreve
                
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='RETR %s\r\n' %os.path.basename(FILE))

                #Server responce opening file
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data= '150 Opening BINARY mode data connection for %s (%i bytes).\r\n' %(os.path.basename(FILE),
                                                                                             len(open(FILE,'rb').read())))
            elif self.METHOD == 'PUT':
                #Client request file STORE
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='STOR %s\r\n' %os.path.basename(FILE))
                
                #server responce
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data= '150 Ok to send data.\r\n')
            elif self.METHOD == 'APPEND':
                #Client request file APPEND
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='APPE %s\r\n' %os.path.basename(FILE))

                #server responce
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data= '150 Ok to send data.\r\n')
            
        #lets switch to src_dst and remember our command values
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []

        if self.METHOD == 'GET':
            
            # SERVER SEND FILE
            self.Flows['FTP_DATA'].Download_File(FILE = FILE,
                                                rlength = self.rlength,
                                                 )
        else:
            #ClIENT SEND FILE
            self.Flows['FTP_DATA'].Upload_File(FILE = FILE,
                                              rlength = self.rlength)

      
        #FIN DATA CONNECTION
        self.Flows['FTP_DATA'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_DATA'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_DATA'].packets = []

    
        #Server send complete command
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                             data= '226 Transfer complete.\r\n',
                                                             )
        

        #Client Acknowledge 
        self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)
       
        #client quit
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'QUIT\r\n')

        #server say goodbye
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '221 Goodbye.\r\n')
        #FIN
        
        self.Flows['FTP_COMMAND'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []
        return self.Packets

    def FTP_TEST_DATACOMMANDAFTERSYNC(self,
                                      ):
        FILE = self.FILES[0]
        self.Packets = []
        #step 1 FTP login
        print 'setting up command'
        self.FTP_INIT(FlowName = 'FTP_COMMAND',
                      dport = self.cdport,
                      sport = self.csport,
                      )
        
        #switch back to command ports
        if self.Passive == False:
            #Server ready to send data
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='150 Ok to send data.\r\n')
        else:
            #client acknowledge
            self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)
            #client send type
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='%s\r\n' %self.FTPTYPE)

            #server response switch to binary
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='200 Switching to %s mode.\r\n' %self.ServerResponseType)

            #Acknowledgement on client connection
            self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)

            if self.METHOD == 'GET':
                #client request filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='SIZE %s\r\n' %os.path.basename(FILE))

                #Server responce filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='213 %i\r\n' %len(open(FILE,'rb').read()))
                #Client request file retreve
                
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='RETR %s\r\n' %os.path.basename(FILE))

                #Server responce opening file
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data= '150 Opening BINARY mode data connection for %s (%i bytes).\r\n' %(os.path.basename(FILE),
                                                                                             len(open(FILE,'rb').read())))
            elif self.METHOD == 'PUT':
                #Client request file STORE
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='STOR %s\r\n' %os.path.basename(FILE))
                
                #server responce
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data= '150 Ok to send data.\r\n')
            elif self.METHOD == 'APPEND':
                #Client request file APPEND
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='APPE %s\r\n' %os.path.basename(FILE))

                #server responce
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data= '150 Ok to send data.\r\n')

        
        #lets switch to src_dst and remember our command values
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []
        
        #Step2 Sync FTP DATA
        print 'syncing up data flow'
        self.Setup_Flow(FlowName='FTP_DATA',
                        dport = self.ddport,
                        sport = self.dsport,)

        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_DATA'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_DATA'].packets = []
        
        if self.Passive == True:
            #Client makes passive request
            print 'sending pasv command'
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'PASV\r\n')

            o1, o2, o3, o4  = self.dst.split('.')
            d1 = self.ddport/256
            d2 = self.ddport - (256*d1)

            #client set port
            data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= data)
        else:
            #port set for client to connect to server
            print 'sending port command'
            o1, o2, o3, o4  = self.src.split('.')
            d1 = self.dsport/256
            d2 = self.dsport - (256*d1)

            #client set port
            data = 'PORT %s,%s,%s,%s,%i,%i\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data= data)

        

        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []
            
        

        if self.METHOD == 'GET':
            
            # SERVER SEND FILE
            self.Flows['FTP_DATA'].Download_File(FILE = FILE,
                                                rlength = self.rlength,
                                                 )
        else:
            #ClIENT SEND FILE
            self.Flows['FTP_DATA'].Upload_File(FILE = FILE,
                                              rlength = self.rlength)

      
        #FIN DATA CONNECTION
        self.Flows['FTP_DATA'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_DATA'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_DATA'].packets = []

    
        #Server send complete command
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                             data= '226 Transfer complete.\r\n',
                                                             )
        

        #Client Acknowledge 
        self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)
       
        #client quit
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'QUIT\r\n')

        #server say goodbye
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '221 Goodbye.\r\n')
        #FIN
        
        self.Flows['FTP_COMMAND'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []
        return self.Packets
    def FTP_MGET_TEST(self,
                      ):
        self.Packets = []
        assert type(self.FILES) == list or type(self.FILES) == tuple, 'for multiple get test must get list of files'


        #step 1 FTP 
        self.FTP_INIT(FlowName = 'FTP_COMMAND',
                      dport = self.cdport,
                      sport = self.csport,)


        #RUN INIT LIST COMMAND
        if self.Passive == True:

            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data='PASV\r\n')

            o1, o2, o3, o4  = self.dst.split('.')
            d1 = (self.ddport)/256
            d2 = (self.ddport) - (256*d1)

            #client set port
            data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data=data)
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_COMMAND'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_COMMAND'].packets = []

            #sync
            #Step2 Sync FTP DATA
            self.Setup_Flow(FlowName='FTP_DATA',
                            dport = self.ddport,
                            sport = self.dsport,)
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_DATA'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_DATA'].packets = []
            
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                             data='LIST\r\n')
            
        else:
            o1, o2, o3, o4  = self.src.split('.')
            d1 = self.dsport/256
            d2 = self.dsport - (256*d1)
            
            data = 'PORT %s,%s,%s,%s,%i,%i\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
           
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data=data)
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data='200 PORT command successful. Consider using PASV.')
            
            
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                             data='LIST\r\n')
                                                                 

            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_COMMAND'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_COMMAND'].packets = []
            
            #sync
            #Step2 Sync FTP DATA
            self.Setup_Flow( FlowName='FTP_DATA',
                             dport = 20,
                             sport = self.dsport,
                             )
            
            self.Packets += self.Flows['FTP_DATA'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_DATA'].packets = []
                                                                 
                                                                

                                                                 
        #Server ready to send data
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='150 Here comes the directory listing.\r\n')


        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []


        listing = []
        for FILE in self.FILES:
             assert os.path.exists(FILE) == True, '%s does not exist' %FILE
             listing.append('-rw-r--r--    1 0        0           %i Apr 21 06:28 %s\r\n' %(len(open(FILE,'rb').read()), os.path.basename(FILE)))


        DATALEN = 0
        DATA = ''
        for i in range(len(listing)):
            DATALEN += len(listing[i])
            DATA += listing[i]
            if DATALEN >  self.rlength - 100: #ip headers should not get up to 100
                self.Flows['FTP_DATA'].ConStruct_Packet_With_Data(fromSrc = False,
                                                              data=DATA)
                self.Flows['FTP_DATA'].ConStruct_Packet_Without_Data(fromSrc = True)
                DATALEN = 0
                DATA = ''
            if i == len(listing) -1:
                self.Flows['FTP_DATA'].ConStruct_Packet_With_Data(fromSrc = False,
                                                              data=DATA)

        #FIN DATA CONNECTION
        self.Flows['FTP_DATA'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_DATA'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_DATA'].packets = []
        ##FINISHED WITH THE LIST COMMAND

        
        #Server ready to send data
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='226 Directory send OK.\r\n')
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='CWD %s.\r\n' %self.CWD)
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='250 Directory successfully changed.\r\n')
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='%s\r\n' %self.FTPTYPE)
        #server response switch to binary
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='200 Switching to %s mode.\r\n' %self.ServerResponseType)

        


        ###NOW LETS SEND THE FILES

        for i in range(len(self.FILES)):
            FILE = self.FILES[i]
            assert os.path.exists(FILE) == True, '%s does not exist' %FILE    

            if self.Passive == True:
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='SIZE %s\r\n' %os.path.basename(FILE))

                #Server responce filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data='213 %i\r\n' %len(open(FILE,'rb').read()))

                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                     data='PASV\r\n')

                o1, o2, o3, o4  = self.dst.split('.')
                d1 = (self.ddport + i + 1)/256
                d2 = (self.ddport + i + 1) - (256*d1)

                #client set port
                data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data=data)

                self.Packets += self.Flows['FTP_COMMAND'].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_COMMAND'].packets = []
            
                #Step2 Sync FTP DATA
                self.Setup_Flow(FlowName='FTP_DATA%i' %i,
                                dport = self.ddport+i+1,
                                sport = self.dsport+i+1,
                                )
                
                self.Packets += self.Flows['FTP_DATA%i' %i].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_DATA%i' %i].packets = []

                
                #Client request file retreve
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='RETR %s\r\n' %os.path.basename(FILE))

            else:
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='SIZE %s\r\n' %os.path.basename(FILE))

                #Server responce filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data='213 %i\r\n' %len(open(FILE,'rb').read()))
                
                o1, o2, o3, o4  = self.src.split('.')
                d1 = (self.dsport+i + 1)/256
                d2 = (self.dsport+i + 1) - (256*d1)
                
                data = 'PORT %s,%s,%s,%s,%i,%i\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
               
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                     data=data)
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data='200 PORT command successful. Consider using PASV.') 
                
                 #Client request file retreve
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='RETR %s\r\n' %os.path.basename(FILE))
                self.Packets += self.Flows['FTP_COMMAND'].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_COMMAND'].packets = []
                #Step2 Sync FTP DATA
                self.Setup_Flow(FlowName='FTP_DATA%i' %i,
                                dport = 20,
                                sport = self.dsport+i+1,)
                self.Packets += self.Flows['FTP_DATA%i' %i].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_DATA%i' %i].packets = []

            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '150 Opening BINARY mode data connection for %s (%i bytes).\r\n' %(os.path.abspath(FILE),
                                                                                                                                          len(open(FILE,'rb').read())))
        

            self.Packets += self.Flows['FTP_COMMAND'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_COMMAND'].packets = []

            #SERVER SEND FILE
            self.Flows['FTP_DATA%i' %i].Download_File(FILE = FILE,
                                                      rlength = self.rlength)
            
            #FIN DATA CONNECTION
            self.Flows['FTP_DATA%i' %i].Fin_Flow()
            
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_DATA%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_DATA%i' %i].packets = []

        
            #Server send complete command
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '226 Transfer complete.\r\n',
                                                                 )

        #Client Acknowledge 
        self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)
       
        #client quit
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'QUIT\r\n')

        #server say goodbye
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '221 Goodbye.\r\n')
        #FIN
        self.Flows['FTP_COMMAND'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []

        return self.Packets
    def FTP_MGET_SAMEDPTEST(self,
                     IncrementDATASEQ = True):
        self.Packets = []
        assert type(self.FILES) == list or type(self.FILES) == tuple, 'for multiple get test must get list of files'

        
        #step 1 FTP 
        self.FTP_INIT(FlowName = 'FTP_COMMAND',
                      dport = self.cdport,
                      sport = self.csport,)

        #RUN INIT LIST COMMAND
        if self.Passive == True:

            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data='PASV\r\n')

            o1, o2, o3, o4  = self.dst.split('.')
            d1 = (self.ddport)/256
            d2 = (self.ddport) - (256*d1)

            #client set port
            data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data=data)
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_COMMAND'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_COMMAND'].packets = []

            #sync
            #Step2 Sync FTP DATA
            self.Setup_Flow(FlowName='FTP_DATA',
                            dport = self.ddport,
                            sport = self.dsport,)
            
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_DATA'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_DATA'].packets = []
            
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                             data='LIST\r\n')
            
        else:
            o1, o2, o3, o4  = self.src.split('.')
            d1 = self.dsport/256
            d2 = self.dsport - (256*d1)
            
            data = 'PORT %s,%s,%s,%s,%i,%i\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
           
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                 data=data)
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data='200 PORT command successful. Consider using PASV.')
            
            
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                             data='LIST\r\n')
                                                                 

            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_COMMAND'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_COMMAND'].packets = []
            
            #sync
            #Step2 Sync FTP DATA
            self.Setup_Flow(FlowName='FTP_DATA',
                            dport = 20,
                            sport = self.dsport,)
            
            self.Packets += self.Flows['FTP_DATA'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_DATA'].packets = []
                                                                 
                                                                

                                                                 
        #Server ready to send data
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='150 Here comes the directory listing.\r\n')


        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []

        listing = []
        for FILE in self.FILES:
             assert os.path.exists(FILE) == True, '%s does not exist' %FILE
             listing.append('-rw-r--r--    1 0        0           %i Apr 21 06:28 %s\r\n' %(len(open(FILE,'rb').read()), os.path.basename(FILE)))


        DATALEN = 0
        DATA = ''
        for i in range(len(listing)):
            DATALEN += len(listing[i])
            DATA += listing[i]
            if DATALEN >  self.rlength - 100: #ip headers should not get up to 100
                self.Flows['FTP_DATA'].ConStruct_Packet_With_Data(fromSrc = False,
                                                              data=DATA)
                self.Flows['FTP_DATA'].ConStruct_Packet_Without_Data(fromSrc = True)
                DATALEN = 0
                DATA = ''
            if i == len(listing) -1:
                self.Flows['FTP_DATA'].ConStruct_Packet_With_Data(fromSrc = False,
                                                              data=DATA)
                
        #FIN DATA CONNECTION
        seq, ack = self.Flows['FTP_DATA'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_DATA'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_DATA'].packets = []
        ##FINISHED WITH THE LIST COMMAND
        
        #remember last flow seq
        if IncrementDATASEQ == True:
            DATAClientSeq = seq
            DATAServerSeq = ack
        else:
            DATAClientSeq = 0
            DATAServerSeq = 0
        
        #Server ready to send data
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='226 Directory send OK.\r\n')
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='CWD %s.\r\n' %self.CWD)
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='250 Directory successfully changed.\r\n')
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='%s\r\n' %self.FTPTYPE)
        #server response switch to binary
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                data='200 Switching to %s mode.\r\n' %self.ServerResponseType)

        


        ###NOW LETS SEND THE FILES

        for i in range(len(self.FILES)):
            
            FILE = self.FILES[i]
            assert os.path.exists(FILE) == True, '%s does not exist' %FILE    

            if self.Passive == True:
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='SIZE %s\r\n' %os.path.basename(FILE))

                #Server responce filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data='213 %i\r\n' %len(open(FILE,'rb').read()))

                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                     data='PASV\r\n')

                o1, o2, o3, o4  = self.dst.split('.')
                d1 = (self.ddport)/256
                d2 = (self.ddport) - (256*d1)

                #client set port
                data = '227 Entering Passive Mode (%s,%s,%s,%s,%i,%i).\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data=data)

                self.Packets += self.Flows['FTP_COMMAND'].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_COMMAND'].packets = []
            
                #Step2 Sync FTP DATA
                self.InitClientSeq = DATAClientSeq+1
                self.InitServerSeq = DATAServerSeq+1
                self.Setup_Flow(FlowName='FTP_DATA%i' %i,
                                dport = self.ddport,
                                sport = self.dsport,
                                )
                
                self.Packets += self.Flows['FTP_DATA%i' %i].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_DATA%i' %i].packets = []

                
                #Client request file retreve
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='RETR %s\r\n' %os.path.basename(FILE))

            else:
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                    data='SIZE %s\r\n' %os.path.basename(FILE))

                #Server responce filesize
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data='213 %i\r\n' %len(open(FILE,'rb').read()))
                
                o1, o2, o3, o4  = self.src.split('.')
                d1 = (self.dsport)/256
                d2 = (self.dsport) - (256*d1)
                
                data = 'PORT %s,%s,%s,%s,%i,%i\r\n' %(o1, o2, o3, o4, int(d1), int(d2))
               
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                     data=data)
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                     data='200 PORT command successful. Consider using PASV.') 
                
                 #Client request file retreve
                self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                                data='RETR %s\r\n' %os.path.basename(FILE))
                self.Packets += self.Flows['FTP_COMMAND'].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_COMMAND'].packets = []
                #Step2 Sync FTP DATA
                self.InitClientSeq = DATAClientSeq+100000
                self.InitServerSeq = DATAServerSeq+100000
                self.Setup_Flow(FlowName='FTP_DATA%i' %i,
                                dport = 20,
                                sport = self.dsport,)
                
                self.Packets += self.Flows['FTP_DATA%i' %i].packets
                #clear out old packets not added to main packet stream
                self.Flows['FTP_DATA%i' %i].packets = []

                
                
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '150 Opening BINARY mode data connection for %s (%i bytes).\r\n' %(os.path.abspath(FILE),
                                                                                                                                          len(open(FILE,'rb').read())))
        

            self.Packets += self.Flows['FTP_COMMAND'].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_COMMAND'].packets = []

            #SERVER SEND FILE
            self.Flows['FTP_DATA%i' %i].Download_File(FILE = FILE,
                                                      rlength = self.rlength)
            
            #FIN DATA CONNECTION
            seq, ack= self.Flows['FTP_DATA%i' %i].Fin_Flow()
            
            #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
            self.Packets += self.Flows['FTP_DATA%i' %i].packets
            #clear out old packets not added to main packet stream
            self.Flows['FTP_DATA%i' %i].packets = []
            if IncrementDATASEQ == True:
                DATAClientSeq = seq
                DATAServerSeq = ack
            else:
                DATAClientSeq = 0
                DATAServerSeq = 0
                #Server send complete command
            self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                                 data= '226 Transfer complete.\r\n',
                                                                 )

        #Client Acknowledge 
        self.Flows['FTP_COMMAND'].ConStruct_Packet_Without_Data(fromSrc = True)
       
        #client quit
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'QUIT\r\n')

        #server say goodbye
        self.Flows['FTP_COMMAND'].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '221 Goodbye.\r\n')
        #FIN
        self.Flows['FTP_COMMAND'].Fin_Flow()
        
        #now lets add all the packets in flow to our main packet stream and clear out the command packet stream
        self.Packets += self.Flows['FTP_COMMAND'].packets
        #clear out old packets not added to main packet stream
        self.Flows['FTP_COMMAND'].packets = []


        return self.Packets
    
if __name__ == '__main__':
    self = FTP_Support()
    #from scapy.utils import PcapWriter
    for Method in ['GET',
                   #'PUT',
                   #'APPEND',
                   ]:
        self.SetVariables(METHOD = Method,
                              dmac = '11:22:33:44:55:66',
                              smac = '22:33:44:55:66:77',
                              TYPE= 'IPv4',
                              src = '1.1.1.1',
                              dst = '2.2.2.2',
                              dsport = 12344,
                              ddport = 12345,
                              csport = 33333,
                              cdport = 21,
                              ftpuser = 'root',
                              ftppassword = 'passwprd',
                              ServerDir = '/',
                              CWD = '/',
                              Passive = True,
                              FTPTYPE = 'I',
                              FILES = ['/data/files/Malicious_DOC.doc',
                                       #'/data/files/Benign_DOC.doc',
                                       ],
                              InitClientSeq = 1,
                              InitServerSeq = 1,
                              rlength = 1500,
                              INTF = 'eth0',
                              SEGMENTS = 1)
        
        PACKETS = self.FTP_TEST_DATACOMMANDAFTERSYNC()
        wrpcap('FTP_%s_DATA_SYNCAFTER.pcap' %Method, PACKETS)
     
