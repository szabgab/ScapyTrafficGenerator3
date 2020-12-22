import itertools
import os
import random

### for ssl ###implement later###
##import base64
##import hashlib
##from Crypto import Random
##from Crypto.Cipher import AES
################################




def HexCodeInteger(INT,
                   HexCodes=2,
                   Swap=True):
    val = hex(INT)[2:]

    if len(str(val)) % 2 == 0:
        val = val
    else:
        val = '0' + val
    #print 'val', val

    hexvalue =  ('0' * ((2*HexCodes) - len(val))) + val
    #print 'hexval', hexvalue, len(hexvalue)


    hexdecode= ''
    if Swap:
        for i in range(HexCodes):
            i += 1
            start = -2*i
            end = len(hexvalue) -((i-1)*2)
            #print 'start', start
            #print 'end', end
            #print str(hexvalue)[(-2*i):(len(hexvalue) -((i-1)*2))]
            hexdecode += hexvalue[start:end].decode('hex')
    else:
        for i in range(HexCodes):
            start = i*2
            end = start + 2
            hexdecode += hexvalue[start:end].decode('hex')

    return hexdecode
    #now lets split our hexes into


    #return hexvalue.decode('hex')

def int_to_two_hex(INT,

                   Swap=True
                   ):
    return HexCodeInteger(INT,
                          Swap=Swap
                          )


def int_to_four_hex(INT,

                    Swap=True
                    ):
    return HexCodeInteger(INT,
                          HexCodes=4,
                          Swap=Swap
                          )

def int_to_eight_hex(INT,
                    Swap=True
                    ):
    return HexCodeInteger(INT,
                          HexCodes=8,
                          Swap=Swap
                          )

def stringtohex(STRING):
    assert isinstance(STRING,basestring)
    val = ''
    for s in STRING:
        v = hex(ord(s))[2:]
        if len(str(val)) % 2 == 0:
            v = v
        else:
            v = '0' + v
        val += v

    hexvalue = ('0' * ((2 * len(STRING)) - len(val))) + val
    #print 'hexval', hexvalue, len(hexvalue)

    hexdecode = ''
    for i in range(len(STRING)):
        start = i * 2
        end = start + 2
        hexdecode += hexvalue[start:end].decode('hex')
    return hexdecode


def padTextafter(text,
                 pad='\x00',
                 Start=None,
                 End=None):
    assert isinstance(text, basestring)
    rval = ''
    for i in text:
        rval +=  i +pad # .upper()

    if Start:
        rval = Start + rval
    if End:
        rval = rval + End
    return rval
def padTextwith(text,
                pad='\x00',
                Start=None,
                End = None,):
    assert isinstance(text,basestring)
    rval = ''
    for i in text:
        rval += pad + i  # .upper()

    if Start:
        rval = Start+rval
    if End:
        rval = rval+End
    return rval

def AsciiEndodeNameInt(name,
                       scope=None,
                       ):
    print 'to do'

def AsciiEncodeNameCode(name,
                      scope=None,
                      ):


    assert isinstance(name, basestring), 'name is not a string. it is %s' % type(name)
    name = str(name)
    if len(name) > 20:
        name = name[:20]
        print 'domain name is more than 20, lets be simple and just take the first 20'
    elif len(name) == 20:
        name = name
    else:
        for i in range(20 - len(name)):
            name += ' '

    encodedName = ''

    for i in name:
        encodedName += ASCII_CODE_MAP[i.upper()]

    if scope:
        encodedName += '.%s' % scope.upper()

    return encodedName

def IpToBin(ip = '1.1.1.1'):
    return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
def BinToIp(BinIp):
    assert len(BinIp) == 32, 'not valid ipv4 address'
    oct1 = int(BinIp[:8],2)
    oct2 = int(BinIp[8:16],2)
    oct3 = int(BinIp[16:24],2)
    oct4 = int(BinIp[24:32],2)
    return '%i.%i.%i.%i' %(oct1,oct2,oct3,oct4)

def GetIpsInNetwork(ip = '1.1.1.1',
                 netmask = 24):
    #lets first get the binary value of the ip address
    BinIp = IpToBin(ip = ip)
    assert len(BinIp) == 32, 'not valid ipv4 address'

    #Match on all matching bits
    IpAddresses = []
    BinStart = BinIp[0:int(netmask)]
    BitsRemaining = 32 - int(netmask)
    ListofRemainingBit = []
    for i in map(''.join, itertools.product('01',repeat=BitsRemaining)):
        if BitsRemaining > 7 and int(i,2) == 0:
            pass
        else:
            ListofRemainingBit.append(i)
    #print 'len' ,len(ListofRemainingBit)
    #return BinStart, ListofRemainingBit
    ips = []
    i = 1
    for rem in ListofRemainingBit:
        i+=1
        ips.append(BinToIp(BinStart+rem))
       
    
    return ips
def GetRandomIpInRange(IpList):
    assert type(IpList) == tuple or type(IpList) == list, 'IpList is a %s not a list or tuple' %type(IpList)
    return IpList[random.randint(0,len(IpList))]
    

def GenerateRandomIp():
    oct1 = random.randint(1,255)
    oct2 = random.randint(0,255)
    oct3 = random.randint(0,255)
    oct4 = random.randint(1,255)

    return '%i.%i.%i.%i' %(oct1,oct2,oct3,oct4)
def GenerateRandomIpv6():
    Value1 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value2 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value3 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value4 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value5 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value6 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value7 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    Value8 = ''.join([random.choice('0123456789abcdef') for i in range(4)
                    ])
    
    return '%s:%s:%s:%s:%s:%s:%s:%s' %(Value1,
                                 Value2,
                                 Value3,
                                 Value4,
                                 Value5,
                                 Value6,
                                 Value7,
                                 Value8)
                    
                    
def GenerateRandomMac():

    Value1 = random.choice('0123456789ABCDEF') + random.choice('26AE')
    Value2 = ''.join([random.choice('0123456789ABCDEF') for i in range(2)])
    Value3 = ''.join([random.choice('0123456789ABCDEF') for i in range(2)])
    Value4 =''.join([random.choice('0123456789ABCDEF') for i in range(2)]) 
    Value5 = ''.join([random.choice('0123456789ABCDEF') for i in range(2)])
    Value6 = ''.join([random.choice('0123456789ABCDEF') for i in range(2)])
    return '%s:%s:%s:%s:%s:%s' %(Value1,
                                 Value2,
                                 Value3,
                                 Value4,
                                 Value5,
                                 Value6)


def IsAsciiFile(File):
    assert os.path.exists(File) == True, "%s path does not exist" %File
    read = open(File,'rb').read()
    for Value in map(ord,read):
        if Value < 0:
            return False
        if Value > 127:
            return False
    return True

def RamdomRawData(size=200):
    data = ''
    for i in range(size):
        data += chr(random.randint(0,127))
    return data
             

def RandomSafePortGenerator():
    return random.randint(49152,65535)

def RandomSafeSeqGenerator():
    return random.randint(1,3000000000)
def ListRandomizer(LIST):
    assert type(LIST) == tuple or type(LIST) == list, 'must be list and is %s' %str(type(LIST))
    return random.sample(LIST,len(LIST))

def set_files_list(PDir):
    """
    This function create a list of test cases 

    Input:
        PayloadDir ==> directory to be defined only if environmental variable PayloadDir does not exist'
    
    Flow of function:
    returns list of files from the Payload directory that have the name malicious or benign in it
    """
    #print 'setting files list for dir', PDir
    TestFiles = []
    assert PDir != None, 'need to define ParentDir that hosts all malicious and benign files'
    assert os.path.exists(PDir) == True, '%s/%s does not exist' %(os.getcwd(), PDir)
    for root,dirs,files in os.walk(PDir):
        for File in files:
            myfilestring = '%s/%s' %(root,File)
            TestFiles.append(str(myfilestring))
    assert TestFiles > 0, 'there are no test files'
    #log_robot_message ('test files are %s' %str(self.TestFiles))
    #print TestFiles
    return TestFiles

##get value by calling File_Modifyer(FILE).output.getvalue()
class File_Modifyer():
    def __init__(self,
                 FILE,
                 OutputFile= 'testing',
                 AddBytes = 200):
        self.file = FILE
        self.output = OutputFile
        self.bytelist = []
        self.AddBytes = AddBytes
        self.retrieve_bytelist()
        self.append_random_bytes_to_output()
    
    def retrieve_bytelist(self):
        '''
        this function read the file into a byte list for randomizing data at end of file
        :return:
        '''
        assert self.file != None, 'must define file'
        assert os.path.exists(self.file) == True, '%s does not exist' %self.file
        for value in open(self.file).read():
            self.bytelist.append(value)
    def append_random_bytes_to_output(self):
        '''
        this function puts randomized data from bytelist and puts it into io stream
        :param AddBytes: bytes to add at end of stream
        :return:
        '''
        assert self.output != None, 'must define io file first'
        assert len(self.bytelist) != 0, 'bytelist has no value'
        assert self.AddBytes > 0 ,'%s is not greater then zero or is not an integer type is %s' %(str(self.AddBytes), str(type(self.AddBytes)))
        f = open(self.output, 'wb')
        f.write(open(self.file).read())
        for i in range(self.AddBytes):
            try:
                f.write(self.bytelist[random.randint(0,len(self.bytelist))])
            except IndexError:
                pass
                
        f.close()
##class AESCipher():
##    def __init__(self, key): 
##        self.bs = 32
##        self.key = hashlib.sha256(key.encode()).digest()
##
##    def encrypt(self, raw):
##        base64.b64encode(raw)
##        raw = self._pad(raw)
##        iv = Random.new().read(AES.block_size)
##        cipher = AES.new(self.key, AES.MODE_CBC, iv)
##        return(iv + cipher.encrypt(raw))
##        #return base64.b64encode(iv + cipher.encrypt(raw))
##    def decrypt(self, enc):
##        enc = base64.b64encode(enc)
##        enc = base64.b64decode(enc)
##        iv = enc[:AES.block_size]
##        cipher = AES.new(self.key, AES.MODE_CBC, iv)
##        return self._unpad(cipher.decrypt(enc[AES.block_size:])).encode('latin-1', 'ignore')
##
##    def _pad(self, s):
##        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
##
##    @staticmethod
##    def _unpad(s):
##        return s[:-ord(s[len(s)-1:])] 
##
    
if __name__=='__main__':
    #print int_to_eight_hex(1000)
    print int_to_two_hex(1000, Swap=False)
    #print stringtohex('NTLMSSP')
