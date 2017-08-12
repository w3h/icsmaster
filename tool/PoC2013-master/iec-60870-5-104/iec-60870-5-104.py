#!/usr/bin/env python

"""
File: iec-60870-5-104.py
Desc: IEC-60870-5-104 (IEC 104) protocol discovery tool. Power of Community 2013 conference release. 
      
"""

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "0.1"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"


import os
import sys
import logging
import socket
import struct

from os.path import abspath
from os.path import join as jpath

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', filename='iec-60870-5-104.log', filemode='wb')


def recv_from_socket(sock, rsize=1):
    recv = ''
    try:
        while True:
            r = sock.recv(rsize)
            if r:
                recv += r
            else:
                break
    except:
        pass
    return recv    

def iec104(dst):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack('ii', int(2), 0))  # 2 sec timeout
    try:
        sock.connect(dst)
    except:
        return '', -1
    # =========================================================================
    
    TESTFR = [
        # iec 104 apci layer
        0x68, # start
        0x04, # APDU len
        0x43, # type 0100 0011
        0x00, 0x00, 0x00  # padding 
        
    ]

    sock.send(''.join(map(chr,TESTFR)))
    recv = recv_from_socket(sock)
    if recv:
        logging.info('{0}'.format(dst))
        logging.debug('iec104 TESTFR : recv: %s' % recv.encode('hex'))
        print "testfr recv: %s" % recv.encode('hex')
    else:
        print "testfr: nothing received"
        return recv, -1
    
    # =========================================================================
    
    STARTDT = [
        # iec 104 apci layer
        0x68, # start
        0x04, # APDU len
        0x07, # type 0000 0111
        0x00, 0x00, 0x00 # padding 

    ]

    sock.send(''.join(map(chr,STARTDT)))
    recv = recv_from_socket(sock)
    if recv:
        logging.info('{0}'.format(dst))
        logging.debug('iec104 STARTDT : recv: %s' % recv.encode('hex'))
        #print "recv: %r" % recv
        print "startdt recv: %s" % recv.encode('hex')
    else:
        print 'startdt: nothing received'
        return recv, -1
    
    # if received 2 packets - STARTDT con + ME_EI_NA_1 Init  - full length should be 6+6+10 bytes
    if len(recv) == 22:
        asdu_addr, = struct.unpack('<H', recv[16:18])
        print "ASDU address: %d" % asdu_addr
        sock.close()
        return recv, asdu_addr
    # =========================================================================

    C_IC_NA_1_broadcast = [

        # iec 104 apci layer
        0x68, # start
        0x0e, # apdu len
        0x00, 0x00, # type + tx
        0x00, 0x00, # rx 

        # iec 104 asdu layer
        0x64, # type id: C_IC_NA_1, interrogation command
        0x01, # numix
        0x06, # some stuff
        0x00, # OA 
        0xff, 0xff, # addr 65535
        0x00, # IOA 
        0x00, 0x00, 0x00 # 0x14 

    ]

    sock.send(''.join(map(chr,C_IC_NA_1_broadcast)))
    recv = recv_from_socket(sock)
    if recv:
        logging.info('{0}'.format(dst))
        logging.debug('iec104 C_IC_NA_1_broadcast : recv: %s' % recv.encode('hex'))
        #print "recv: %r" % recv
        print "c_ic_na_1 recv: %s" % recv.encode('hex')
    else:
        print 'c_ic_na_1_broadcast: nothing received'
        return recv, -1

    #print "recv: %s" % recv.encode('hex')
    try:
        assert len(recv)==16
        asdu_addr, = struct.unpack('<H', recv[10:12])
        print "ASDU address: %d" % asdu_addr
    except:
        asdu_addr = -1
    finally:
        sock.close()
    
    return recv, asdu_addr

def print_help():
    print """
IEC-60870-5-104 (IEC 104) protocol discovery tool. Power of Community 2013 conference release. 
Usage: %s <file_of_ip_list> """ % sys.argv[0]
    return

if __name__ == '__main__':
    
    print_help()
    raw_input("press <PoC2013> key to continue...")
    for l in open(sys.argv[1]):
        ip = l.strip()
        if ip:
            print "process %s" % ip
            dst = (ip, 2404)
            recv, asdu_addr = iec104(dst)
            print "ip: {0}, recv: {1}, asdu_addr: {2}".format(ip, recv.encode('hex'), asdu_addr)

