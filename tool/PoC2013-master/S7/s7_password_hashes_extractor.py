#!/usr/bin/env python

"""
File: s7_password_hashes_extractor.py
Desc: password hashes extractor from Siemens Simatic TIA Portal project file
"""

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "1.1"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"

import sys
import os
import re
import optparse
from binascii import hexlify
from hashlib import sha1

cfg_result_hashes = 's7_password_hashes_extractor.hashes'

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-p', dest="project_file", help="PEData.plf filepath")
    options, args = parser.parse_args()
    
    if not options.project_file:
        parser.print_help()
        sys.exit()
    
    data = open(options.project_file, 'rb').read()
    print "read PEData file %s, size 0x%X bytes" % (options.project_file, os.path.getsize(options.project_file))
    
    print "sample of used passwords and hashes:"
    for p in ['123', '1234AaBb', '1234AaB', '1111111111aaaaaaaaaa']:
        print "\t%s : %s" % (p, sha1(p).hexdigest())

    re_pattern = re.compile('456e6372797074656450617373776f72[a-f0-9]{240,360}000101000000[a-f0-9]{40}')
    possible_hashes = [s[-40:] for s in re_pattern.findall(hexlify(data))]
    possible_hashes = reduce(lambda x, y: x if y in x else x + [y], possible_hashes, [])
    open(cfg_result_hashes, 'w').write('\n'.join(possible_hashes))
    
    total_hashes = len(possible_hashes)
    print "found %d sha1 hashes, ordered by histrory list:" % (total_hashes)
    for h in possible_hashes:
        pos = possible_hashes.index(h) + 1
        if pos == total_hashes:
            print '\thash %d: %s\t(current)' % (pos, h)
        else:
            print '\thash %d: %s' % (pos, h)
