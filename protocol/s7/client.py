"""
Snap7 client used for connection to a siemens7 server.
"""
import re
from ctypes import c_int, c_char_p, byref, sizeof, c_uint16, c_int32, c_byte
from ctypes import c_void_p

import logging

import snap7
from snap7 import six
from snap7.snap7types import S7Object, buffer_type, buffer_size, BlocksList
from snap7.snap7types import TS7BlockInfo, param_types, cpu_statuses

from snap7.common import check_error, load_library, ipv4
from snap7.snap7exceptions import Snap7Exception

logger = logging.getLogger(__name__)


def error_wrap(func):
    """Parses a s7 error code returned the decorated function."""
    def f(*args, **kw):
        code = func(*args, **kw)
        check_error(code, context="client")
    return f


class Client(object):
    """
    A snap7 client
    """
    def __init__(self):
        self.library = load_library()
        self.pointer = False
        self.create()

    def create(self):
        """
        create a SNAP7 client.
        """
        logger.info("creating snap7 client")
        self.library.Cli_Create.restype = c_void_p
        self.pointer = S7Object(self.library.Cli_Create())

    def destroy(self):
        """
        destroy a client.
        """
        logger.info("destroying snap7 client")
        return self.library.Cli_Destroy(byref(self.pointer))

    def plc_stop(self):
        """
        stops a client
        """
        logger.info("stopping plc")
        return self.library.Cli_PlcStop(self.pointer)

    def plc_cold_start(self):
        """
        cold starts a client
        """
        logger.info("cold starting plc")
        return self.library.Cli_PlcColdStart(self.pointer)

    def plc_hot_start(self):
        """
        hot starts a client
        """
        logger.info("hot starting plc")
        return self.library.Cli_PlcHotStart(self.pointer)

    def get_cpu_state(self):
        """
        Retrieves CPU state from client
        """
        state = c_int(0)
        self.library.Cli_GetPlcStatus(self.pointer,byref(state))
        
        try:
            status_string = cpu_statuses[state.value]
        except KeyError:
            status_string = None
        
        if not status_string:
            raise Snap7Exception("The cpu state (%s) is invalid" % state.value)
        
        logging.debug("CPU state is %s" % status_string)
        return status_string

    @error_wrap
    def disconnect(self):
        """
        disconnect a client.
        """
        logger.info("disconnecting snap7 client")
        return self.library.Cli_Disconnect(self.pointer)

    @error_wrap
    def connect(self, address, rack, slot, tcpport=102):
        """
        Connect to a S7 server.

        :param address: IP address of server
        :param rack: rack on server
        :param slot: slot on server.
        """
        logger.info("connecting to %s:%s rack %s slot %s" % (address, tcpport,
                                                             rack, slot))

        self.set_param(snap7.snap7types.RemotePort, tcpport)
        return self.library.Cli_ConnectTo(
            self.pointer, c_char_p(six.b(address)),
            c_int(rack), c_int(slot))

    def db_read(self, db_number, start, size):
        """This is a lean function of Cli_ReadArea() to read PLC DB.

        :returns: user buffer.
        """
        logger.debug("db_read, db_number:%s, start:%s, size:%s" %
                     (db_number, start, size))

        type_ = snap7.snap7types.wordlen_to_ctypes[snap7.snap7types.S7WLByte]
        data = (type_ * size)()
        result = (self.library.Cli_DBRead(
            self.pointer, db_number, start, size,
            byref(data)))
        check_error(result, context="client")
        return bytearray(data)

    @error_wrap
    def db_write(self, db_number, start, data):
        """
        Writes to a DB object.

        :param start: write offset
        :param data: bytearray
        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        size = len(data)
        cdata = (type_ * size).from_buffer(data)
        logger.debug("db_write db_number:%s start:%s size:%s data:%s" %
                     (db_number, start, size, data))
        return self.library.Cli_DBWrite(self.pointer, db_number, start, size,
                                        byref(cdata))

    def full_upload(self, _type, block_num):
        """
        Uploads a full block body from AG.
        The whole block (including header and footer) is copied into the user
        buffer.

        :param block_num: Number of Block
        """
        _buffer = buffer_type()
        size = c_int(sizeof(_buffer))
        block_type = snap7.snap7types.block_types[_type]
        result = self.library.Cli_FullUpload(self.pointer, block_type,
                                             block_num, byref(_buffer),
                                             byref(size))
        check_error(result, context="client")
        return bytearray(_buffer), size.value

    def upload(self, block_num):
        """
        Uploads a block body from AG

        :param data: bytearray
        """
        logger.debug("db_upload block_num: %s" % (block_num))

        block_type = snap7.snap7types.block_types['DB']
        _buffer = buffer_type()
        size = c_int(sizeof(_buffer))

        result = self.library.Cli_Upload(self.pointer, block_type, block_num,
                                         byref(_buffer), byref(size))

        check_error(result, context="client")
        logger.info('received %s bytes' % size)
        return bytearray(_buffer)

    @error_wrap
    def download(self, data, block_num=-1):
        """
        Downloads a DB data into the AG.
        A whole block (including header and footer) must be available into the
        user buffer.

        :param block_num: New Block number (or -1)
        :param data: the user buffer
        """
        type_ = c_byte
        size = len(data)
        cdata = (type_ * len(data)).from_buffer(data)
        result = self.library.Cli_Download(self.pointer, block_num,
                                           byref(cdata), size)
        return result

    def db_get(self, db_number):
        """Uploads a DB from AG.
        """
        logging.debug("db_get db_number: %s" % db_number)
        _buffer = buffer_type()
        result = self.library.Cli_DBGet(
            self.pointer, db_number, byref(_buffer),
            byref(c_int(buffer_size)))
        check_error(result, context="client")
        return bytearray(_buffer)

    def read_area(self, area, dbnumber, start, size):
        """This is the main function to read data from a PLC.
        With it you can read DB, Inputs, Outputs, Merkers, Timers and Counters.

        :param dbnumber: The DB number, only used when area= S7AreaDB
        :param start: offset to start writing
        :param size: number of units to read
        """
        assert area in snap7.snap7types.areas.values()
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        logging.debug("reading area: %s dbnumber: %s start: %s: amount %s: "
                      "wordlen: %s" % (area, dbnumber, start, size, wordlen))
        data = (type_ * size)()
        result = self.library.Cli_ReadArea(self.pointer, area, dbnumber, start,
                                           size, wordlen, byref(data))
        check_error(result, context="client")
        return bytearray(data)

    @error_wrap
    def write_area(self, area, dbnumber, start, data):
        """This is the main function to write data into a PLC. It's the
        complementary function of Cli_ReadArea(), the parameters and their
        meanings are the same. The only difference is that the data is
        transferred from the buffer pointed by pUsrData into PLC.

        :param dbnumber: The DB number, only used when area= S7AreaDB
        :param start: offset to start writing
        :param data: a bytearray containing the payload
        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        size = len(data)
        logging.debug("writing area: %s dbnumber: %s start: %s: size %s: "
                      "type: %s" % (area, dbnumber, start, size, type_))
        cdata = (type_ * len(data)).from_buffer(data)
        return self.library.Cli_WriteArea(self.pointer, area, dbnumber, start,
                                          size, wordlen, byref(cdata))

    def read_multi_vars(self, items):
        """This function read multiple variables from the PLC.

        :param items: list of S7DataItem objects
        :returns: a tuple with the return code and a list of data items
        """
        result = self.library.Cli_ReadMultiVars(self.pointer, byref(items),
                                                c_int32(len(items)))
        check_error(result, context="client")
        return result, items

    def list_blocks(self):
        """Returns the AG blocks amount divided by type.

        :returns: a snap7.types.BlocksList object.
        """
        logging.debug("listing blocks")
        blocksList = BlocksList()
        result = self.library.Cli_ListBlocks(self.pointer, byref(blocksList))
        check_error(result, context="client")
        logging.debug("blocks: %s" % blocksList)
        return blocksList

    def list_blocks_of_type(self, blocktype, size):
        """This function returns the AG list of a specified block type."""

        blocktype = snap7.snap7types.block_types.get(blocktype)

        if not blocktype:
            raise Snap7Exception("The blocktype parameter was invalid")

        logging.debug("listing blocks of type: %s size: %s" %
                      (blocktype, size))

        data = (c_int * 10)()
        count = c_int(size)
        result = self.library.Cli_ListBlocksOfType(
            self.pointer, blocktype,
            byref(data),
            byref(count))

        logging.debug("number of items found: %s" % count)

        check_error(result, context="client")
        return data

    def get_block_info(self, blocktype, db_number):
        """Returns the block information for the specified block."""

        blocktype = snap7.snap7types.block_types.get(blocktype)

        if not blocktype:
            raise Snap7Exception("The blocktype parameter was invalid")

        logging.debug("retrieving block info for block %s of type %s" %
                      (db_number, blocktype))

        data = TS7BlockInfo()

        result = self.library.Cli_GetAgBlockInfo(
            self.pointer, blocktype,
            db_number, byref(data))
        check_error(result, context="client")
        return data

    @error_wrap
    def set_session_password(self, password):
        """Send the password to the PLC to meet its security level."""
        assert len(password) <= 8, 'maximum password length is 8'
        return self.library.Cli_SetSessionPassword(self.pointer,
                                                   c_char_p(six.b(password)))

    @error_wrap
    def clear_session_password(self):
        """Clears the password set for the current session (logout)."""
        return self.library.Cli_ClearSessionPassword(self.pointer)

    def set_connection_params(self, address, local_tsap, remote_tsap):
        """
        Sets internally (IP, LocalTSAP, RemoteTSAP) Coordinates.
        This function must be called just before Cli_Connect().

        :param address: PLC/Equipment IPV4 Address, for example "192.168.1.12"
        :param local_tsap: Local TSAP (PC TSAP)
        :param remote_tsap: Remote TSAP (PLC TSAP)
        """
        assert re.match(ipv4, address), '%s is invalid ipv4' % address
        result = self.library.Cli_SetConnectionParams(self.pointer, address,
                                                      c_uint16(local_tsap),
                                                      c_uint16(remote_tsap))
        if result != 0:
            raise Snap7Exception("The parameter was invalid")

    def set_connection_type(self, connection_type):
        """
        Sets the connection resource type, i.e the way in which the Clients
        connects to a PLC.

        :param connection_type: 1 for PG, 2 for OP, 3 to 10 for S7 Basic
        """
        result = self.library.Cli_SetConnectionType(self.pointer,
                                                    c_uint16(connection_type))
        if result != 0:
            raise Snap7Exception("The parameter was invalid")

    def get_connected(self):
        """
        Returns the connection status

        :returns: a boolean that indicates if connected.
        """
        connected = c_int32()
        result = self.library.Cli_GetConnected(self.pointer, byref(connected))
        check_error(result, context="client")
        return bool(connected)

    def ab_read(self, start, size):
        """
        This is a lean function of Cli_ReadArea() to read PLC process outputs.
        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        data = (type_ * size)()
        logging.debug("ab_read: start: %s: size %s: " % (start, size))
        result = self.library.Cli_ABRead(self.pointer, start, size,
                                         byref(data))
        check_error(result, context="client")
        return bytearray(data)

    def ab_write(self, start, data):
        """
        This is a lean function of Cli_WriteArea() to write PLC process
        outputs
        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        size = len(data)
        cdata = (type_ * size).from_buffer(data)
        logging.debug("ab write: start: %s: size: %s: " % (start, size))
        return self.library.Cli_ABWrite(
            self.pointer, start, size, byref(cdata))

    def as_ab_read(self, start, size):
        """
        This is the asynchronous counterpart of client.ab_read().
        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        data = (type_ * size)()
        logging.debug("ab_read: start: %s: size %s: " % (start, size))
        result = self.library.Cli_AsABRead(self.pointer, start, size,
                                           byref(data))
        check_error(result, context="client")
        return bytearray(data)

    def as_ab_write(self, start, data):
        """
        This is the asynchronous counterpart of Cli_ABWrite.
        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        size = len(data)
        cdata = (type_ * size).from_buffer(data)
        logging.debug("ab write: start: %s: size: %s: " % (start, size))
        return self.library.Cli_AsABWrite(
            self.pointer, start, size, byref(cdata))

    @error_wrap
    def as_compress(self, time):
        """
        This is the asynchronous counterpart of client.compress().
        """
        return self.library.Cli_AsCompress(self.pointer, time)

    def copy_ram_to_rom(self):
        """

        """
        return self.library.Cli_AsCopyRamToRom(self.pointer)

    def as_ct_read(self):
        """

        """
        return self.library.Cli_AsCTRead(self.pointer)

    def as_ct_write(self):
        """

        """
        return self.library.Cli_AsCTWrite(self.pointer)

    def as_db_fill(self):
        """

        """
        return self.library.Cli_AsDBFill(self.pointer)

    def as_db_get(self, db_number):
        """
        This is the asynchronous counterpart of Cli_DBGet.
        """
        logging.debug("db_get db_number: %s" % db_number)
        _buffer = buffer_type()
        result = self.library.Cli_AsDBGet(self.pointer, db_number,
                                          byref(_buffer),
                                          byref(c_int(buffer_size)))
        check_error(result, context="client")
        return bytearray(_buffer)

    def as_db_read(self, db_number, start, size):
        """
        This is the asynchronous counterpart of Cli_DBRead.

        :returns: user buffer.
        """
        logger.debug("db_read, db_number:%s, start:%s, size:%s" %
                     (db_number, start, size))

        type_ = snap7.snap7types.wordlen_to_ctypes[snap7.snap7types.S7WLByte]
        data = (type_ * size)()
        result = (self.library.Cli_AsDBRead(self.pointer, db_number, start,
                                            size,  byref(data)))
        check_error(result, context="client")
        return bytearray(data)

    def as_db_write(self, db_number, start, data):
        """

        """
        wordlen = snap7.snap7types.S7WLByte
        type_ = snap7.snap7types.wordlen_to_ctypes[wordlen]
        size = len(data)
        cdata = (type_ * size).from_buffer(data)
        logger.debug("db_write db_number:%s start:%s size:%s data:%s" %
                     (db_number, start, size, data))
        return self.library.Cli_AsDBWrite(
            self.pointer, db_number, start, size,
            byref(cdata))

    @error_wrap
    def as_download(self, data, block_num=-1):
        """
        Downloads a DB data into the AG asynchronously.
        A whole block (including header and footer) must be available into the
        user buffer.

        :param block_num: New Block number (or -1)
        :param data: the user buffer
        """
        size = len(data)
        type_ = c_byte * len(data)
        cdata = type_.from_buffer(data)
        return self.library.Cli_AsDownload(self.pointer, block_num,
                                           byref(cdata), size)

    @error_wrap
    def compress(self, time):
        """
        Performs the Memory compress action.

        :param time: Maximum time expected to complete the operation (ms).
        """
        return self.library.Cli_Compress(self.pointer, time)

    @error_wrap
    def set_param(self, number, value):
        """Sets an internal Server object parameter.
        """
        logger.debug("setting param number %s to %s" % (number, value))
        type_ = param_types[number]
        return self.library.Cli_SetParam(self.pointer, number,
                                         byref(type_(value)))

    def get_param(self, number):
        """Reads an internal Client object parameter.
        """
        logger.debug("retreiving param number %s" % number)
        type_ = param_types[number]
        value = type_()
        code = self.library.Cli_GetParam(self.pointer, c_int(number),
                                         byref(value))
        check_error(code)
        return value.value
