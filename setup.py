from distutils.core import setup

try:
    long_description = open('SCAPYTRAFFIC_README.rst').read()
except:
    long_description = 'see https://pypi.python.org/pypi/ScapyTrafficGenerator'

'''
import pypandoc

try:
    long_description = pypandoc.convert('SCAPYTRAFFIC_README.md', 'rst')
    print 'waaa'
except(IOError, ImportError):
    long_description = open('SCAPYTRAFFIC_README.md').read()
    
f = open('SCAPYTRAFFIC_README.rst','w')
f.write(long_description)
f.close()
'''
setup(
    name = 'ScapyTrafficGenerator',
    packages = ['TrafficGenerator',
                'TrafficGenerator/support',
                'TrafficGenerator/support/smb2command',
                'TrafficGenerator/support/smbcommand',
                'TrafficGenerator/scapy',
                'TrafficGenerator/scapy/arch',
                'TrafficGenerator/scapy/arch/windows',
                'TrafficGenerator/scapy/asn1',
                'TrafficGenerator/scapy/contrib',
                'TrafficGenerator/scapy/crypto',
                'TrafficGenerator/scapy/layers',
                'TrafficGenerator/scapy/modules',
                'TrafficGenerator/scapy/tools',
                ],
    long_description=long_description,
    version = '2.19.1',
    description = 'create pcaps, or replay traffic on an interface',
    author = 'Nathan Hosington',
    author_email = 'nathan.hoisington@vipre.com',
    scripts = ['TrafficGenerator/ScapyTrafficGenerator','TrafficGenerator/ScapyPacketSender'],
    #cmdclass = {'install': 'TrafficGenerator/setup.sh'},
    #package_data={'pcaps':'Pcaps/*.pcap'},
    #install_requires=['scapy']

)

