


HEX_CODE_MAP_REVERSE = {
    'A': '4245',
    'B': '4345',
    'C': '4445',
    'D': '4545',
    'E': '4645',
    'F': '4745',
    'G': '4845',
    'H': '4945',
    'I': '4A45',
    'J': '4B45',
    'K': '4C45',
    'L': '4D45',
    'M': '4E45',
    'N': '4F45',
    'O': '5045',
    'P': '4146',
    'Q': '4246',
    'R': '4346',
    'S': '4446',
    'T': '4546',
    'U': '4646',
    'V': '4746',
    'W': '4846',
    'X': '4946',
    'Y': '4A46',
    'Z': '4B46',
    '0': '4144',
    '1': '4244',
    '2': '4344',
    '3': '4444',
    '4': '4544',
    '5': '4644',
    '6': '4744',
    '7': '4844',
    '8': '4944',
    '9': '4A45',
    ' ': '4143',
    '!': '4343',
    '"': '4343',
    '#': '4443',
    '$': '4543',
    '%': '4643',
    '&': '4743',
    "'": '4843',
    '(': '4943',
    ')': '4A43',
    '*': '4B43',
    '+': '4C43',
    ',': '4D45',
    '-': '4E45',
    '.': '4F45',
    '=': '4E44',
    ':': '4B44',
    ';': '4C44',
    '@': '4145',
    '^': '4F46',
    '_': '5046',
    '{': '4C48',
    '}': '4E48',
    '~': '4F48',

}



HEX_CODE_MAP = {}
for k,v in HEX_CODE_MAP_REVERSE.iteritems():
    HEX_CODE_MAP[k] = v[2:]+v[:2]


TERMINATING_HEX_CODE_MAP = {}
for k,v in HEX_CODE_MAP.iteritems():
    TERMINATING_HEX_CODE_MAP[k]= '%X' %(int(v,16) - 512)


ASCII_CODE_MAP ={
    'A': 'EB',
    'B': "EC",
    'C': "ED",
    'D': 'EE',
    'E': "EF",
    'F': "EG",
    'G': 'EH',
    'H': "EI",
    'I': "EJ",
    'J': 'EK',
    'K': "EL",
    'L': "EM",
    'M': 'EN',
    'N': "EO",
    'O': "EP",
    'P': 'FA',
    'Q': "FB",
    'R': "FC",
    'S': 'FD',
    'T': "FE",
    'U': "FF",
    'V': 'FG',
    'W': "FH",
    'X': "FI",
    'Y': 'FJ',
    'Z': "FK",
    '0': "DA",
    '1': 'DB',
    '2': "DC",
    '3': "DD",
    '4': 'DE',
    '5': "DF",
    '6': "DG",
    '7': 'DH',
    '8': "DI",
    '9': "DJ",
    ' ': 'CA',
    '!': "CB",
    '"': "CC",
    '#': 'CD',
    '$': "CE",
    '%': "CF",
    '&': "CG",
    "'": "CH",
    '(': 'CI',
    ')': "CJ",
    '*': "CK",
    '+': "CL",
    ',': "CM",
    '-': 'CN',
    '.': "CO",
    '=': "DN",
    ':': "DK",
    ';': "DL",
    '@': 'EA',
    '^': "FO",
    '_': "FP",
    '{': "HL",
    '}': "HN",
    '~': "HP",
}

CharMap = {}
for k,v in HEX_CODE_MAP_REVERSE.iteritems():
    #print k
    if not CharMap.get(k):
        CharMap[k]={}
    CharMap[k]['hexCodeReverse'] = v

for k,v in HEX_CODE_MAP.iteritems():
    if not CharMap.get(k):
        CharMap[k]={}
    CharMap[k]['hexCode'] = v


for k,v in ASCII_CODE_MAP.iteritems():
    if not CharMap.get(k):
        CharMap[k]={}
    CharMap[k]['ASCIICode'] = v


if __name__ == '__main__':
    import binascii

    print binascii.unhexlify(''.join('C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88'.split()))

