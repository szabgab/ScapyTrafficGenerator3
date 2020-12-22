import logging

import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ScapyPacketGenerator import *
from support.smb2command.Scapy_Control import *
from subprocess import PIPE, Popen
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="set replay interface", required=False, default=None)
    parser.add_argument("-x","--protocol", help="tcp,icmp,udp",required=False, default='tcp')
    parser.add_argument("-s", "--src", help="specify src ip", required=False, default=None)
    parser.add_argument("-d", "--dst", help="specify dst ip", required=False,default=None)
    parser.add_argument("-S", "--sport", help="specify src port", required=False,default=None)
    parser.add_argument("-D", "--dport", help="specify dst port", required=False,default=None)

    args = parser.parse_args()
    ip = IP()
    if args.src:
        ip.src = args.src
    if args.dst:
        ip.dst = args.dst



    if args.protocol.lower() =='tcp':
        tcp = TCP()
        if args.sport:
            tcp.sport=int(args.sport)
        if args.dport:
            tcp.dport=int(args.dport)

        packet = ip/tcp

    elif args.protocol.lower() == 'icmp':
        packet = ip/ICMP()

    elif args.protocol.lower() == 'udp':
        udp = UDP()
        if args.sport:
            udp.sport=int(args.sport)
        if args.dport:
            udp.dport=int(args.dport)
        packet = ip/udp
    elif args.protocol.lower() == 'dns':
        packet = ip/DNS()

    else:
        raise Exception('protocol %s not supported yet' %args.protocol)

    ###lets get the interface
    if args.interface:
        iface = args.interface
    else:
        iface = get_iface_name_matching_destination(args.dst)

    print 'sending packet on interface:', iface, '\n   ', packet.show()
    p = sr1(packet,iface=iface,timeout=2)


    if p:
        print 'packet returned' ,p.show()
        try:
            p[TCP]
            hasTcp=True
        except:
            hasTcp=False

        if hasTcp:
            RST = 0x04
            if p[TCP].flags & RST:
                print 'connection refused'
            #check to see if reset was called
    else:
        print 'packet did not return'



def get_iface_name_matching_destination(dest):
    ''
    #start by getting all interfaces and their ip addresses
    print 'interface was not given,  lets try to dynamically find the correct interface to match %s' %dest

    cmd = "ip route | grep default | awk '{print $5}'"
    s = Popen(cmd, executable='/bin/bash', stdout=PIPE, stderr=PIPE, shell=True)
    stdout, stderr = s.communicate()
    default_interface =  stdout.split('\n')[0].strip('\n').strip()


    if dest:
        try:
            destIPMatchList = GetIpsInNetwork(dest)
            cmd = "ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d'"
            s = Popen(cmd, executable='/bin/bash', stdout=PIPE, stderr=PIPE, shell=True)
            sleep(1)
            stdout, stderr = s.communicate()
            stdout=stdout.strip()
            iflist =  stdout.split('\n')
            for interface in iflist:
                interface = interface.strip('\n').strip()
                ### unfortunately this pip config works only on centos  :(  update later
                ipcmd = "ifconfig %s | grep 'inet' | cut -d: -f2 | awk '{ print $2}'" %interface.replace(':','')
                s = Popen(ipcmd, executable='/bin/bash', stdout=PIPE, stderr=PIPE, shell=True)
                stdout, stderr = s.communicate()
                stdout.strip()
                if stdout:
                    ip = stdout.strip()
                    #print 'interface %s has ip address %s' %(interface,ip)
                    if ip in destIPMatchList:
                        print 'interface %s is on the same network as %s' %(interface,dest)
                        return interface.replace(':','')
                    #else:
                        #print 'interface %s is not on the same network as %s' % (interface, dest)
        except:
            print 'this code was written for centos7,  an error happened, returning default address'

    return default_interface.replace(':','')




if __name__ == '__main__':
    main()
    #print (get_iface_name_matching_destination('10.49.0.1'))