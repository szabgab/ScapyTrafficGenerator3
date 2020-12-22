import logging

import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from support.SMB2_Support import *
from ScapyPacketGenerator import *


def main():
    #SET ALL DEFAULT VALUES
    RLENGTH = 1000
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="set replay interface", required=False,default='eth2' )
    parser.add_argument("-s", "--src", help="specify src ip", required=False, default=GenerateRandomIp())
    parser.add_argument("-d", "--dst", help="specify dst ip", required=False, default=GenerateRandomIp() )
    parser.add_argument("-S", "--sport", help="specify src port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-D", "--dport", help="specify dst port", required=False, default=RandomSafePortGenerator())
    parser.add_argument("-m", "--srcmac", help="specify src mac", required=False, default=GenerateRandomMac())
    parser.add_argument("-M", "--dstmac", help="specify dst mac", required=False, default=GenerateRandomMac())
    parser.add_argument("--login", help="loginname", required=False, default='ClientUser')
    parser.add_argument("--clientdomain", help="client domain", required=False, default='ClientD0M')
    parser.add_argument("--clienthost", "--clientHost", help="client host", required=False,default='ClientHost')
    parser.add_argument("--nbdomain", help="nb domain", required=False, default='2008DOM')
    parser.add_argument("--nbcomp", help="nb computer", required=False, default='2008COMP')
    parser.add_argument("--dnsdomain", help="dns domain", required=False, default='2008DNSDOM')
    parser.add_argument("--dnscomp", help="dns computer", required=False, default='2008DNSCOMP')
    parser.add_argument("--dnstree", help="dns tree", required=False, default='2008DNSTREE')
    parser.add_argument("--treepath", help="path", required=False,default='\\\\nathan\\is\\awesome')
    parser.add_argument("-V", "--service", help="native os of server machine", required=False,default='IPC')
    parser.add_argument("--gretunnel", help="encapsulate with gretunnel", required=False, default=False,action="store_true")
    parser.add_argument("--altermid", help="dont alter mid", required=False, default=True,action="store_false")
    parser.add_argument("-y", "--vlanTagType", help="specify additional response", required=False, default=2048)
    parser.add_argument("-v", "--vlanTag", help="specify vlan tag id", required=False, default=None)
    parser.add_argument("-t", "--type", help="specify vlan tag id", required=False, default='read')
    parser.add_argument("-o", "--scapyoutput", help="specify output file", required=False, default=True, action="store_false")
    parser.add_argument("-F", "--file", help="specify file to transfer", required=False, action='append',default=['/opt/TrafficGen/TestFiles/Malicious_DOC.doc'])

    args = parser.parse_args()
    self = ScapyPacketGenerator()
    FILE = []
    for f in args.file:
        F = f.split(':')
        if len(F) == 1:
            FILE.append(F[0].strip('\n'))
            if str(F[0]).lower() != 'none':
                assert os.path.exists(F[0]), '%s does not exist' % F[0]
        elif len(F) == 2:
            if str(F[0]).lower() == 'random':
                DATAONLY = int(F[1])
                FILE.append('random')
            else:
                if str(F[0]).lower() != 'none':
                    if str(F[0]).lower() != '/opt/TrafficGen/TestFiles/Malicious_DOC.doc':
                        assert os.path.exists(F[0]), '%s does not exist' % F[0]
                randomized = int(F[1].strip('\n'))
                FILE.append(F[0].strip('\n'))
                # lets strip the default if needed
    if len(FILE) > 1:
        FILE.remove('/opt/TrafficGen/TestFiles/Malicious_DOC.doc')

    self.SetupInterface(INTF=args.interface)
    self.SMB2.SetVariables(dmac=args.dstmac,
                           smac=args.srcmac,
                           TYPE=args.type,
                           src=args.src,
                           dst=args.dst,
                           sport=args.sport,
                           dport=args.dport,
                           AlterMID=args.altermid,
                           CLientDomain=args.clientdomain,
                           ClientUser=args.login,
                           ClientHost=args.clienthost,
                           NBDomain=args.nbdomain,
                           NBComp=args.nbcomp,
                           DNSDoman=args.dnsdomain,
                           DNSCOMP=args.dnscomp,
                           DNSTREE=args.dnstree,
                           tree=args.treepath,
                           FILES=FILE,
                           )


    if args.type.lower() == 'read':
        self.Packets= self.SMB2.SMB2Test(Read=True)
    elif args.type.lower() == 'write':
        self.Packets = self.SMB2.SMB2Test(Write=True)
    elif args.type.lower() == 'delete':
        self.Packets = self.SMB2.SMB2Test(Delete=True)
    else:
        print 'NO ACTION TAKEN'
        self.Packets = self.SMB2.SMB2Test()

    if args.gretunnel:
        self.EncasulateGre()
    if args.vlanTag:
        self.EncasulateVlan(vlanTag=int(args.vlanTag),
                            vlanTagType=int(args.vlanTagType))
    if args.scapyoutput == True:
        self.SendPackets()
    else:
        self.SendPackets(Verbose=0)


if __name__ == '__main__':
    main()
