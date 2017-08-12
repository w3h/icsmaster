#!/usr/bin/env python

"""
File: profinet_scanner.noscapy.py
Desc: Profinet discovery tool. Send multicast ethernet packet and receive all answers.
      Extract useful info about devices: PLC, HMI, Workstations.
      Power of Community 2013 conference release. 
      
      No scapy required. Works on *nix systems.
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
import fcntl
import struct
import uuid
import optparse
from binascii import hexlify, unhexlify

def is_printable(data):
    printset = set(string.printable)
    return set(data).issubset(printset)

def get_src_mac_by_interface(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return info[18:24]
    #return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

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
        #data = hexlify(data)
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


if __name__ == '__main__':
    
    print """
Profinet discovery tool. Send multicast ethernet packet and receive all answers.
Extract useful info about devices: PLC, HMI Workstations.
No scapy required.
Power of Community 2013 conference release.
"""
    

    parser = optparse.OptionParser()
    parser.add_option('-i', dest="src_iface", default="", help="source network interface")
    options, args = parser.parse_args()
    parser.print_help()
    raw_input("press <PoC2013> key to continue...")
    src_iface = options.src_iface or 'eth0'
    src_mac = get_src_mac_by_interface(src_iface)

    profinet_dcp_ethernet_frame = {
      'dst_mac' : '\x01\x0e\xcf\x00\x00\x00',
      'src_mac' : src_mac,
      'proto'   : '\x88\x92',
      'payload' : '\xfe\xfe\x05\x00\x04\x01\x00\x02\x00\x80\x00\x04\xff\xff' + '\x00'*26,
    }


    pdef = profinet_dcp_ethernet_frame

    eth_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x8892)
    # set socket recieve timeout 2 seconds
    eth_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack('ii', int(2), 0))
    
    eth_sock.bind(('eth0', 0x8892))
    data = pdef['dst_mac'] + pdef['src_mac'] + pdef['proto'] + pdef['payload']
    eth_sock.send(data)

    recieved_packets = []

    while True:
        try:
            buf = eth_sock.recv(1024)
            print 'recieved: %r' % buf
            if buf:
                recieved_packets.append(buf)
            else:
                break
        except:
            break

    # parse and print result
    result = {}
    for p in recieved_packets:
        p = p.encode('hex')
        print p
        source_mac  = p[12:24]
        packet_type = p[24:28]
        pn_type     = p[28:32]
        packet_load = p[28:]
        #print source_mac, packet_type, packet_load
        if packet_type == '8892' and pn_type == 'feff':
            type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway = parse_load(packet_load, source_mac)
            result[source_mac] = {'load': packet_load}
            result[source_mac]['type_of_station'] = type_of_station
            result[source_mac]['name_of_station'] = name_of_station
            result[source_mac]['vendor_id'] = vendor_id
            result[source_mac]['device_id'] = device_id
            result[source_mac]['device_role'] = device_role
            result[source_mac]['ip_address'] = ip_address
            result[source_mac]['subnet_mask'] = subnet_mask
            result[source_mac]['standard_gateway'] = standard_gateway


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