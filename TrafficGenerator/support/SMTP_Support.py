from time import asctime
import base64

from TCP_flow_control import *
from Scapy_Control import GenerateRandomIp, RandomSafeSeqGenerator


class SMTP_Support():
    def __init__(self):
        self.Packets = []
        self.Flows = {}
    def SetVariables(self,
                     dmac = '11:22:33:44:55:66',
                       smac = '22:33:44:55:66:77',
                       TYPE= 'IPv4',
                       src = '1.1.1.1',
                       dst = '2.2.2.2',
                       sport = 1234,
                       dport = 25,
                       username = 'name',
                       password = 'password',
                       ServerName = 'welcometo.nathan.web',
                   TO='testto@test.com',
                   FROM = 'testfrom@test.com',
                     ):
        self.username=username
        self.password=password
        self.dmac = dmac
        self.smac = smac
        self.src = src
        self.dst = dst
        self.TYPE = TYPE
        self.sport = int(sport)
        self.dport = int(dport)
        self.InitClientSeq = RandomSafeSeqGenerator()
        self.InitServerSeq = RandomSafeSeqGenerator()
        self.ServerName = ServerName
        self.TO = TO
        self.FROM = FROM

    def Setup_Flow(self,
                   FlowName='SMTP', #'FTP_COMMAND' #'FTP_DATA'
                   ):

        #print 'setting flow name', FlowName
        #print 'sync dport', dport, 'with sport', sport

        FlowObject = TCP_flow_control()
        FlowObject.Sync_Flow(dmac = self.dmac,
                               smac = self.smac,
                               TYPE= self.TYPE,
                               src = self.src,
                               dst = self.dst,
                               dport = self.dport,
                               sport = self.sport,
                               InitClientSeq = self.InitClientSeq,
                               InitServerSeq = self.InitServerSeq,
                               )
        self.Flows[FlowName] = FlowObject

    def Connect(self,
                FlowName = 'SMTP',
                ):
        print 'connectiong flow'
        self.Setup_Flow(FlowName)

        #for argument sake lets loop this function for many login users
        usernames = []
        if isinstance(self.username,basestring):
            usernames.append(self.username)
        else:
            usernames = self.username

        for username in usernames:
            # server sendname
            data = '220-%s ESMTP Exim 4.69 #1 %s -0500 \r\n220-We do not authorize the use of this system to transport unsolicited, \r\n220 and/or bulk e-mail.\r\n' %(self.ServerName,asctime())
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= data)
            #send EHLO
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'EHLO GP\r\n')

            #this response is static for now until i understand what it means  HAS PADDING BUT LEAVING OUT
            self.Flows[FlowName].ConStruct_Packet_Without_Data(fromSrc = False,
                                                               )

            #server sendHeaders
            ##not sure why generating random ip just doing it because sample has ip i dont know
            defaultHeaders = '250-%s Hello GP [%s]\r\n250-SIZE 52428800\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250-STARTTLS\r\n250 HELP\r\n' %(self.ServerName, GenerateRandomIp())

            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= defaultHeaders)

            #send AUTH LOGIN
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= 'AUTH LOGIN\r\n')

            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '334 %s\r\n' %str(base64.b64encode('Username:')),
                                                            )
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= '%s\r\n' %str(base64.b64encode(username)),
                                                            )
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '334 %s\r\n' %str(base64.b64encode('Password:')),
                                                            )
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                            data= '%s\r\n' %str(base64.b64encode(self.password)),
                                                            )
            self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                            data= '235 Authentication succeeded\r\n',
                                                            )

    def SendMailWithText(self,
                   FlowName='SMTP',
                   MessageString = 'This is an SMTP Message'):
        print 'sending mail'
        #send from
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data='MAIL FROM: <%s>\r\n' %self.FROM,
                                                        )
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                        data= '250 OK\r\n',
                                                        )

        #send to
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data='RCPT TO: <%s>\r\n' %self.TO,
                                                        )
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                        data= '250 Accepted\r\n',
                                                        )

        #send data
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data=  'DATA\r\n',
                                                        )
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                        data= '354 Enter message, ending with "." on a line by itself\r\n',
                                                        )

        self._boundary = '----=NextPart_' + ''.join([random.choice('0123456789abcdef') for i in range(4)])
        setmessage = ['FROM NAME" <%s>\r\n' %self.FROM,
                      'To: <%s>\r\n' %self.TO,
                      'Subject: SMTP\r\n',
                      'Date: %s\r\n' %str(asctime),
                      'MIME-Version: 1.0\r\n',
                      'Content-Type: multipart/mixed;\r\n',
                      '\tboundary="%s"\r\n' %self._boundary,
                      'X-Mailer: Microsoft Office Outlook 12.0\r\n',
                      '\r\nThis is a multipart message in MIME format.\r\n\r\n',
                      '--%s\r\n' %self._boundary,
                      '\tboundary="%s"\r\n' %self._boundary,
                      'Content-Type: text/plain;\r\n',
                      '\tcharset="us-ascii"\r\n',
                      'Content-Transfer-Encoding: 7bit\r\n',
                      '\r\n%s.\r\n\r\n' %MessageString,
                      '--%s\r\n' %self._boundary,
                      ##ATTACHEMENT WILL BE IN NEXT PART
                      #'Content-Language: en-us\r\n',
                      #'Content-Type: multipart/alternative;\r\n',
                      #etc,
                      '\r\n\r\n.\r\n']
        datasend = ''
        for m in setmessage:
            datasend+=m


        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data=datasend)

        #pcap sample has '250 OK id=1Mugho-0003Dg-Un\r\n'
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data= '250 OK\r\n')


    def Finish(self,
               FlowName='SMTP'):
        print 'closing connection'
        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = True,
                                                        data='QUIT\r\n')

        self.Flows[FlowName].ConStruct_Packet_With_Data(fromSrc = False,
                                                        data='221 %s closing connection\r\n' %self.ServerName)



        self.Flows[FlowName].Fin_Flow()


    def SMTP_CONNECT_NOATTACHMENT(self,
                                  FlowName='SMTP'):
        self.Connect(FlowName=FlowName)
        self.SendMailWithText(FlowName=FlowName)
        self.Finish(FlowName=FlowName)
        return self.Flows[FlowName].packets



if __name__ == '__main__':
    print 'loading class'
    self = SMTP_Support()
    print 'setting variables'
    usernamelist = []
    for i in range(250):
        usernamelist.append('name%i' %i)
    usernamelist += ['name1', 'name2', 'name3', 'name4']
    self.SetVariables(dmac = '11:22:33:44:55:66',
                       smac = '22:33:44:55:66:77',
                       TYPE= 'IPv4',
                       src = '1.1.1.1',
                       dst = '2.2.2.2',
                       sport = 1234,
                       dport = 25,
                       username = usernamelist,
                       password = 'password',
                       ServerName = 'welcometo.nathan.web',
                   TO='testto@test.com',
                   FROM = 'testfrom@test.com',
                      )
    PACKETS = self.SMTP_CONNECT_NOATTACHMENT()
    print '# of packets', len(PACKETS)
    wrpcap('/tmp/scapySMTP.pcap', PACKETS)



