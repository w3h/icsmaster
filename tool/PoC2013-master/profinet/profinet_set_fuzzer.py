#!/usr/bin/env python

"""
File: profinet_set_fuzzer.py
Desc: Profinet SET request fuzzer. Tested on S7-1200/1500 PLC.
      Send Profinet DCP SET request with preconfigured count of packets and preconfigured options/suboptions.
      ALARM! Do not test on real devices! Can destroy them.
      Power of Community 2013 conference release. 
      
      Scapy required. Works on *nix and win* systems.
"""

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "1.3"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"

import sys
import random
import time
import threading
import string
import socket
import struct
import uuid
import optparse

from scapy.all import conf, sniff, srp, Ether
from binascii import hexlify, unhexlify

cfg_sniff_time = 3 # seconds

sniffed_packets = None

dcp_answers = {
                0x00 : 'OK',
                0x01 : 'Options unsupported',
                0x02 : 'Suboption unsupported or no dataset available',
                0x03 : 'Suboption not set',
                0x04 : 'Resource error',
                0x05 : 'SET not possible by local reasons',
                0x06 : 'In operation, SET not possible',
              }


def get_src_iface():
    return conf.iface

def get_src_mac():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])


def sniff_packets(src_iface):
    global sniffed_packets
    sniffed_packets = None
    sniffed_packets = sniff(iface=src_iface, filter='ether proto 0x8892', timeout=cfg_sniff_time)
    return sniffed_packets

def generate_random_hex_bytes(bytes):
    return random.getrandbits(bytes*8)

def generate_random_hex_bytes_as_str(bytes, check=''):
    if not check:
        data = ''.join([ '%02x' % random.randint(1,255) for i in range(1, bytes+1)])
        return data
    else:
        return bytes*check

class DCPSetPacket:
  
    def __init__(self, option, suboption, block_len=0, min_block_len=1, max_block_len=1024, check=''):
        if block_len:
            self.block_len = block_len
        else:
            self.block_len = random.randint(min_block_len, max_block_len)
        self.check = check
        self.packet_format = None
        self.dcp_frame_id = 0xfefd # profinet acyclic realtime id, short
        self.dcp_service_id = 0x04 # get/set service id, byte
        self.dcp_service_type = 0x00 # request, byte
        self.dcp_xid = generate_random_hex_bytes(4) # xid value needed for chain responses, int
        self.dcp_reserved = 0x0000 # reserved, short
        self.dcp_data_length = None  # data length, short
        self.dcp_block_option = option # set option , byte
        self.dcp_block_suboption = suboption # must be random value from () , byte
        self.dcp_block_length = None # short
        self.dcp_block_qualifier = random.choice((0x0000, 0x0001)) # short
        #self.dcp_block_qualifier = random.choice((0x0000, ))
        self.dcp_block_data = self.generate_block_data()
        self.dcp_padding = self.block_len%2 # 0 - padding not need, 1 - need, byte
        # padding = 1 ^ len(name_of_station)%2
        self.payload = None

    def generate_block_data(self):
        return generate_random_hex_bytes_as_str(self.block_len, self.check)

    def create_packet_format(self):
        self.packet_format = struct.Struct('> H B B I H H B B H H')

    def prepare_packet(self):
        self.create_packet_format()
        self.dcp_block_length = 2 + self.block_len
        self.dcp_data_length = 1 + 1+ 2 + self.dcp_block_length
        pack_args = [ self.dcp_frame_id,
                      self.dcp_service_id, 
                      self.dcp_service_type, 
                      self.dcp_xid, 
                      self.dcp_reserved,
                      self.dcp_data_length,
                      self.dcp_block_option, 
                      self.dcp_block_suboption, 
                      self.dcp_block_length,
                      self.dcp_block_qualifier,
                    ]
        self.payload = self.packet_format.pack(*pack_args).encode('hex')
  
    def get_full_hex_payload(self):
        full_hex_payload = self.payload + self.dcp_block_data
        if self.dcp_padding:
            full_hex_payload += '00'
        return full_hex_payload

if __name__ == '__main__':
    print """
Profinet SET request fuzzer. Tested on S7-1200/1500 PLC.
Send Profinet DCP SET request with preconfigured count of packets and preconfigured options/suboptions.
ALARM! Do not test on real devices! Can destroy them.
Power of Community 2013 conference release. 

Scapy required. Works on *nix and win* systems.
"""
    src_mac = get_src_mac()
    parser = optparse.OptionParser()
    parser.add_option('-d', '--dest-mac', dest="dst_mac", default="00:1c:06:0a:a7:a4", help="destination MAC address")
    
    parser.print_help()
    raw_input("press <PoC2013> key to continue...")
    
    options, args = parser.parse_args()
    
    dst_mac = options.dst_mac

    options_data =    {

                     0x01 : ( 0x01, 0x02 ), # ip
                     0x02 : ( 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ), # device
                     0x03 : ( 12, 43, 54, 55, 60, 61, 81, 97, 255, 0 ), # dhcp
                     0x04 : ( 0x01, 0x02, 0x03 ), # reserved
                     0x05 : ( 0x01, 0x02, 0x03, 0x04, 0x05 ), # control
                     0x06 : ( 0x00, 0x01 ), # device initiative
                     0x80 : ( 0x02, ), # manuf
                     0x81 : ( 0x02, ), # manuf
                     0x82 : ( 0x02, ), # manuf
                     0x83 : ( 0x02, ), # manuf
                     0x84 : ( 0x02, ), # manuf
                     0x85 : ( 0x02, ), # manuf
                     0x86 : ( 0x02, ), # manuf
                     0xff : ( 0x00, 0x01, 0x02, 0xff ), # all selector
                    }

    packets_per_suboption = 1000
 
  
    for option in options_data.keys():
        fh_log = open('profinet_set_fuzzer.log_%02x' % option, 'w', 0)
        fh_err = open('profinet_set_fuzzer.err_%02x' % option, 'w', 0)
        for suboption in options_data[option]:
            packet_with_00 = 0
            packet_with_ff = 0
            for pck_num in range(1, packets_per_suboption+1):
                info_text = "option: %02x, suboption: %02x, pck_num: %d" % (option, suboption, pck_num)
                fh_log.write("%s\n" % info_text)
                p = None
                try:
                    block_len = 0 # 0 - random len
                    if packet_with_00 and not p:
                        packet_with_00 = 0
                        p = DCPSetPacket(option, suboption, block_len=block_len, check='00')
                    elif packet_with_ff and not p:
                        packet_with_ff = 0
                        p = DCPSetPacket(option, suboption, block_len=block_len, check='ff')
                    else:
                        p = DCPSetPacket(option, suboption, block_len=block_len)
                    p.prepare_packet()
                  
                    payload = p.get_full_hex_payload()
                    fh_log.write("request : %s\n" % payload)
                    pp = Ether(type=0x8892, src=src_mac, dst=dst_mac)/payload.decode('hex')
                    ans, unans = srp(pp, timeout=cfg_sniff_time)
                    response = 'NO RESPONSE'
                    answer_code = -1
                    if ans:
                        response = hexlify(ans[0][1].load)
                        answer_code = int(response[36:38])
                    else:
                        fh_err.write("%s\nresponse: %s\n" % (info_text, str(ans)))
                    fh_log.write("response: %s\n" % response)
                    if answer_code != -1:
                        answer_text = dcp_answers.has_key(answer_code) and dcp_answers[answer_code] or 'answer unknown'
                        fh_log.write("answer code: %02x, text: %s\n" % (answer_code, answer_text))
                except:
                    fh_log.write("error: %s\n" % str(sys.exc_info()))
                fh_log.write('\n')
        fh_log.close()
        fh_err.close()