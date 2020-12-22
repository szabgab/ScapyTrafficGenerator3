from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from Scapy_Control import *



class SSL_TSL_Supprt():
    def __init__(self):
        self.defaultCipher="RSA_WITH_AES_128_CBC_SHA"
        self.sshcipher=65664
    def simple_clientHello(self,
                           **kwargs):

        version= kwargs.get('tlsrecord_version') or "TLS_1_0"
        if "ssl" in version.lower():
            print 'ssl type'
            clienthello = SSLv2ClientHello(version=version,
                                           #cipher_suites= ['RSA_WITH_AES_128_CBC_SHA']
                                           )
            clientrecord = SSLv2Record(content_type='client_hello')
            return  SSL(records = [clientrecord/clienthello])


        else:
            print 'tls type'
            #TLSExtension(type="supported_groups", length=0x8)/TLSExtEllipticCurves(length=0x6, elliptic_curves=['secp256r1', 'secp384r1', 'secp521r1'])).show()
            tlsclienthello = TLSClientHello()
            tlshandshake = TLSHandshake(type= 'client_hello')
            tlsrecord = TLSRecord(content_type="handshake",
                                  version= kwargs.get('tlsrecord_version') or "TLS_1_0")
            return SSL(records = [tlsrecord/tlshandshake/tlsclienthello] )

    def simple_serverHello(self,
                           **kwargs):
        version= kwargs.get('tlsrecord_version') or "TLS_1_0"
        if "ssl" in version.lower():
            print 'ssl type'
            serverhello = SSLv2ClientHello(version=version)
            return  SSL(records = [SSLv2Record(content_type='server_hello')/SSLv2ClientHello(version=version)/Raw(load=RamdomRawData(400))])

        else:

            #TLSExtension(type="supported_groups", length=0x8)/TLSExtEllipticCurves(length=0x6, elliptic_curves=['secp256r1', 'secp384r1', 'secp521r1'])).show()
            tlsserverhello = TLSServerHello(cipher_suite=self.defaultCipher)
            tlshandshake = TLSHandshake(type= 'server_hello')
            tlsrecord = TLSRecord(content_type="handshake",
                                  version= kwargs.get('tlsrecord_version') or "TLS_1_0")
            return SSL(records = [tlsrecord/tlshandshake/tlsserverhello] )

    def simple_server_certificate(self,
                                  publiccertlen=141,
                                  signaturelen=257,
                                  subject=None,
                                  issuer=None,
                                  **kwargs):
        version= kwargs.get('tlsrecord_version') or "TLS_1_0"


        if not subject:
            subject = 'nathan.s.super.awesome.server.1.0.com'
        if not issuer:
            issuer = 'Nathan Is Super'



        #random value pupblic key
        randompubliccert=RamdomRawData(publiccertlen)

        #random value signature
        randomsignature=RamdomRawData(signaturelen)


        certificate = TLSCertificate(data=X509Cert(signature=ASN1_BIT_STRING(randomsignature),
                                                   pubkey=ASN1_BIT_STRING(randompubliccert),
                                                   #issuer=[X509RDN(oid=ASN1_OID('.2.5.4.3'), value=ASN1_PRINTABLE_STRING('DigiCert SHA2 High Assurance Server CA'))],
                                                   subject=[X509RDN(oid=ASN1_OID('.2.5.4.3'), value=ASN1_PRINTABLE_STRING(subject))],
                                                   issuer=[X509RDN(oid=ASN1_OID('.2.5.4.3'), value=ASN1_PRINTABLE_STRING(issuer))],

                                                   #subject=[X509RDN(oid=ASN1_OID('.2.5.4.3'), value=ASN1_PRINTABLE_STRING('nathan.s.super.awesome.server.1.0.com'))],
                                                   ),
                                     )

        certificatelist = TLSCertificateList(certificates=[certificate])

        certificatehandshake = TLSHandshake(type='certificate')

        record = TLSRecord(version= version,
                           content_type="handshake")

        return SSL(records=[record/certificatehandshake/certificatelist])


    def simple_server_hello_done(self,
                                 **kwargs):

        version= kwargs.get('tlsrecord_version') or "TLS_1_0"

        tlshandshake = TLSHandshake(type= 'server_hello_done')
        tlsrecord = TLSRecord(content_type="handshake",
                              version=version)
        return SSL(records = [tlsrecord/tlshandshake] )

    def simple_ClientKeyExchange(self,
                                 exchangelen=130,
                                 **kwargs):

        version= kwargs.get('tlsrecord_version') or "TLS_1_0"
        if "ssl" in version.lower():
            print 'ssl record version=', version
            return SSL(records = SSLv2Record(content_type="client_master_key")/SSLv2ClientMasterKey(key_argument=RamdomRawData(8)))
        else:
            record = TLSRecord(content_type="handshake",
                                  version= version)
            tlshandshake = TLSHandshake(type= 'client_key_exchange')
            return SSL(records = [record/tlshandshake/TLSClientKeyExchange()/Raw(load=RamdomRawData(exchangelen))])


    def simple_Client_ChangeCipherSpec(self,
                                       **kwargs):
        version= kwargs.get('tlsrecord_version') or "TLS_1_0"
        record = TLSRecord(content_type="change_cipher_spec",
                              version= version)
        cipherSpec = TLSChangeCipherSpec()

        return SSL(records = [record/cipherSpec])

    def simple_Server_ChangeCipherSpec(self,
                                       specmessagelen=21,
                                       **kwargs):
        version= kwargs.get('tlsrecord_version') or "TLS_1_0"
        record = TLSRecord(content_type="change_cipher_spec",
                              version= version)
        cipherSpec = TLSChangeCipherSpec(message=RamdomRawData(specmessagelen))

        return SSL(records = [record/cipherSpec])

    def encrypted_data(self,
                       encryptlen=40):
        return SSL(records = [TLSRecord(content_type=0)/TLSCiphertext(data=RamdomRawData(encryptlen))])

    def Finished(self,
                 finisheddatalen=12,
                 #rawlen=16,
                 **kwargs):
        version= kwargs.get('tlsrecord_version') or "TLS_1_0"
        record = TLSRecord(content_type="handshake",
                              version= version)

        return SSL(records = [record/TLSHandshake(type="finished")/TLSFinished(data=RamdomRawData(finisheddatalen))])#/TLSHandshake(type=247)/Raw(load=RamdomRawData(rawlen))])



if __name__=="__main__":
    pcap = "/home/nathanhoisington/test.pcap"
    SSLSUP = SSL_TSL_Supprt()
    packetstart = Ether()/IP(src="1.2.3.4", dst='4.3.2.1',flags="DF")/TCP(sport=12345, dport=443, flags="PA", ack=1111, seq=3222)
    packetend = SSLSUP.simple_clientHello()
    packet=packetstart/packetend
    packet.show2()
    #packet = SSLSUP.simple_serverHello()
    #packet = SSLSUP.simple_server_certificate()
    #packet = SSLSUP.simple_server_hello_done()
    #packet = SSLSUP.simple_ClientKeyExchange()
    #packet = SSLSUP.simple_Client_ChangeCipherSpec()
    #packet = SSLSUP.Finished()
    #packet = SSLSUP.simple_Server_ChangeCipherSpec()
    #packet = SSLSUP.Finished()
    #print ''
    #packet.show()
    #print ''
    #print 'show 2'
    #print ''
    #packet.show2()
    #print ''
    wrpcap(pcap,packet)
    #print ''
    #print 'after writing'
    #print ''
    #print ''
    #rdpcap(pcap)[0].show2()




'''
for scapy
y = rdpcap('testing/ts-test/Tools/TrafficGenerator/Pcaps/tls2.pcap')
clienthello=3[3]
serverhello = y[5]
cert = y[7]
serverhellodone = y[9]
clientkeyExchange = y[11]
clientchangecipherspec = y[13]
clientfinished = y[15]
serverchangecipherspec=y[17]
serverfinished=y[19]

'''