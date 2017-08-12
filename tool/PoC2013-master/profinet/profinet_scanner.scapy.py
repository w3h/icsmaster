#!/usr/bin/env python

"""
File: profinet_scanner.scapy.py
Desc: Profinet discovery tool. Send multicast ethernet packet and receive all answers.
      Extract useful info about devices: PLC, HMI, Workstations.
      Power of Community 2013 conference release. 
      
      Scapy required. Works on *nix and win* systems.
"""

__author__ = "Aleksandr Timorin"
__copyright__ = "Copyright 2013, Positive Technologies"
__license__ = "GNU GPL v3"
__version__ = "0.1"
__maintainer__ = "Aleksandr Timorin"
__email__ = "atimorin@gmail.com"
__status__ = "Development"


import sys
import time
import threading
import string
import socket
import struct
import uuid
import optparse
from binascii import hexlify, unhexlify
from scapy.all import conf, sniff, srp, Ether

cfg_dst_mac = '01:0e:cf:00:00:00' # Siemens family
cfg_sniff_time = 2 # seconds

sniffed_packets = None

def get_src_iface():
    return conf.iface

def get_src_mac():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

def sniff_packets(src_iface):
    global sniffed_packets
    sniffed_packets = sniff(iface=src_iface, filter='ether proto 0x8892', timeout=cfg_sniff_time)

def is_printable(data):
    printset = set(string.printable)
    return set(data).issubset(printset)

def parse_load(data, src):
    type_of_station = None
    name_of_station = None
    vendor_id = None
    device_id = None
    device_role = None
    ip_address = None
    subnet_mask = None
    standard_gateway = None
    try:
        data = hexlify(data)
        PROFINET_DCPDataLength = int(data[20:24], 16)
        start_of_Block_Device_Options = 24
        Block_Device_Options_DCPBlockLength = int(data[start_of_Block_Device_Options + 2*2:start_of_Block_Device_Options + 4*2], 16)
        
        start_of_Block_Device_Specific = start_of_Block_Device_Options + Block_Device_Options_DCPBlockLength*2 + 4*2
        Block_Device_Specific_DCPBlockLength = int(data[start_of_Block_Device_Specific+2*2:start_of_Block_Device_Specific+4*2], 16)
        
        padding = Block_Device_Specific_DCPBlockLength%2
        
        start_of_Block_NameOfStation = start_of_Block_Device_Specific + Block_Device_Specific_DCPBlockLength*2 + (4+padding)*2
        Block_NameOfStation_DCPBlockLength = int(data[start_of_Block_NameOfStation+2*2:start_of_Block_NameOfStation+4*2], 16)
        
        padding = Block_NameOfStation_DCPBlockLength%2

        start_of_Block_Device_ID = start_of_Block_NameOfStation + Block_NameOfStation_DCPBlockLength*2 + (4+padding)*2
        Block_DeviceID_DCPBlockLength = int(data[start_of_Block_Device_ID+2*2:start_of_Block_Device_ID+4*2], 16)
        __tmp = data[start_of_Block_Device_ID+4*2:start_of_Block_Device_ID+4*2+Block_DeviceID_DCPBlockLength*2][4:]
        vendor_id, device_id = __tmp[:4], __tmp[4:]
        
        padding = Block_DeviceID_DCPBlockLength%2

        start_of_Block_DeviceRole = start_of_Block_Device_ID + Block_DeviceID_DCPBlockLength*2 + (4+padding)*2
        Block_DeviceRole_DCPBlockLength = int(data[start_of_Block_DeviceRole+2*2:start_of_Block_DeviceRole+4*2], 16)
        device_role = data[start_of_Block_DeviceRole+4*2:start_of_Block_DeviceRole+4*2+Block_DeviceRole_DCPBlockLength*2][4:6]
        
        padding = Block_DeviceRole_DCPBlockLength%2

        start_of_Block_IPset = start_of_Block_DeviceRole + Block_DeviceRole_DCPBlockLength*2 + (4+padding)*2
        Block_IPset_DCPBlockLength = int(data[start_of_Block_IPset+2*2:start_of_Block_IPset+4*2], 16)
        __tmp = data[start_of_Block_IPset+4*2:start_of_Block_IPset+4*2+Block_IPset_DCPBlockLength*2][4:]
        ip_address_hex, subnet_mask_hex, standard_gateway_hex = __tmp[:8], __tmp[8:16], __tmp[16:]
        ip_address = socket.inet_ntoa(struct.pack(">L", int(ip_address_hex, 16)))
        subnet_mask = socket.inet_ntoa(struct.pack(">L", int(subnet_mask_hex, 16)))
        standard_gateway = socket.inet_ntoa(struct.pack(">L", int(standard_gateway_hex, 16)))
        
        tos = data[start_of_Block_Device_Specific+4*2 : start_of_Block_Device_Specific+4*2+Block_Device_Specific_DCPBlockLength*2][4:]
        nos = data[start_of_Block_NameOfStation+4*2 : start_of_Block_NameOfStation+4*2+Block_NameOfStation_DCPBlockLength*2][4:]
        type_of_station = unhexlify(tos)
        name_of_station = unhexlify(nos)
        if not is_printable(type_of_station):
            type_of_station = 'not printable'
        if not is_printable(name_of_station):
            name_of_station = 'not printable'
    except:
        print "%s: %s" % (src, str(sys.exc_info()))
    return type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway


def create_packet_payload():
    pass

if __name__ == '__main__':

    print """
Profinet discovery tool. Send multicast ethernet packet and receive all answers.
Extract useful info about devices: PLC, HMI Workstations.
Scapy required.
Power of Community 2013 conference release.
"""


    src_mac = get_src_mac()
    parser = optparse.OptionParser()
    parser.add_option('-i', dest="src_iface", default="", help="source network interface")
    parser.print_help()
    raw_input("press <PoC2013> key to continue...")
    options, args = parser.parse_args()
    
    src_iface = options.src_iface or get_src_iface()
    
    # run sniffer
    t = threading.Thread(target=sniff_packets, args=(src_iface,))
    t.setDaemon(True)
    t.start()

    # create and send broadcast profinet packet
    payload =  'fefe 05 00 04010002 0080 0004 ffff '
    payload = payload.replace(' ', '')

    pp = Ether(type=0x8892, src=src_mac, dst=cfg_dst_mac)/payload.decode('hex')
    ans, unans = srp(pp)

    # wait sniffer...
    t.join()

    # parse and print result
    result = {}
    for p in sniffed_packets:
        if hex(p.type) == '0x8892' and p.src != src_mac:
            result[p.src] = {'load': p.load}
            type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway = parse_load(p.load, p.src)
            result[p.src]['type_of_station'] = type_of_station
            result[p.src]['name_of_station'] = name_of_station
            result[p.src]['vendor_id'] = vendor_id
            result[p.src]['device_id'] = device_id
            result[p.src]['device_role'] = device_role
            result[p.src]['ip_address'] = ip_address
            result[p.src]['subnet_mask'] = subnet_mask
            result[p.src]['standard_gateway'] = standard_gateway

    print "found %d devices" % len(result)
    print "{0:17} : {1:15} : {2:15} : {3:9} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}".format('mac address', 'type of station', 
                                                                                              'name of station', 'vendor id', 
                                                                                              'device id', 'device role', 'ip address',
                                                                                              'subnet mask', 'standard gateway')
    for (mac, profinet_info) in result.items():
        p = result[mac]
        print "{0:17} : {1:15} : {2:15} : {3:9} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}".format(mac, 
                                                                                                p['type_of_station'], 
                                                                                                p['name_of_station'], 
                                                                                                p['vendor_id'],
                                                                                                p['device_id'],
                                                                                                p['device_role'],
                                                                                                p['ip_address'],
                                                                                                p['subnet_mask'],
                                                                                                p['standard_gateway'],
                                                                                                )

      
