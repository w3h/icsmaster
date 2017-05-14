"""
This module contains utility functions for working with PLC DB objects.
There are functions to work with the raw bytearray data snap7 functions return
In order to work with this data you need to make python able to work with the
PLC bytearray data.

For example code see test_util.py and example.py in the example folder.


example::

    spec/DB layout

    # Byte index    Variable name  Datatype
    layout=\"\"\"
    4	          ID             INT
    6             NAME	         STRING[6]

    12.0          testbool1      BOOL
    12.1          testbool2      BOOL
    12.2          testbool3      BOOL
    12.3          testbool4      BOOL
    12.4          testbool5      BOOL
    12.5          testbool6      BOOL
    12.6          testbool7      BOOL
    12.7          testbool8      BOOL
    13            testReal       REAL
    17            testDword      DWORD
    \"\"\"

    client = snap7.client.Client()
    client.connect('192.168.200.24', 0, 3)

    # this looks confusing but this means uploading from the PLC to YOU
    # so downloading in the PC world :)

    all_data = client.upload(db_number)

    simple:

    db1 = snap7.util.DB(
        db_number,              # the db we use
        all_data,               # bytearray from the plc
        layout,                 # layout specification DB variable data
                                # A DB specification is the specification of a
                                # DB object in the PLC you can find it using
                                # the dataview option on a DB object in PCS7

        17+2,                   # size of the specification 17 is start
                                # of last value
                                # which is a DWORD which is 2 bytes,

        1,                      # number of row's / specifications

        id_field='ID',          # field we can use to identify a row.
                                # default index is used
        layout_offset=4,        # sometimes specification does not start a 0
                                # like in our example
        db_offset=0             # At which point in 'all_data' should we start
                                # reading. if could be that the specification
                                # does not start at 0
    )

    Now we can use db1 in python as a dict. if 'ID' contains
    the 'test' we can identify the 'test' row in the all_data bytearray

    To test of you layout matches the data from the plc you can
    just print db1[0] or db['test'] in the example

    db1['test']['testbool1'] = 0

    If we do not specify a id_field this should work to read out the
    same data.

    db1[0]['testbool1']

    to read and write a single Row from the plc. takes like 5ms!

    db1['test'].write()

    db1['test'].read()


"""
try:
    # try with the standard library
    from collections import OrderedDict
except ImportError:
    # fallback to Python 2.6-2.4 back-port
    from ordereddict import OrderedDict


import struct
import logging
from snap7 import six
import re

logger = logging.getLogger(__name__)


def get_bool(_bytearray, byte_index, bool_index):
    """
    Get the boolean value from location in bytearray
    """
    index_value = 1 << bool_index
    byte_value = _bytearray[byte_index]
    current_value = byte_value & index_value
    return current_value == index_value


def set_bool(_bytearray, byte_index, bool_index, value):
    """
    Set boolean value on location in bytearray
    """
    assert value in [0, 1, True, False]
    current_value = get_bool(_bytearray, byte_index, bool_index)
    index_value = 1 << bool_index

    # check if bool already has correct value
    if current_value == value:
        return

    if value:
        # make sure index_v is IN current byte
        _bytearray[byte_index] += index_value
    else:
        # make sure index_v is NOT in current byte
        _bytearray[byte_index] -= index_value


def set_int(_bytearray, byte_index, _int):
    """
    Set value in bytearray to int
    """
    # make sure were dealing with an int
    _int = int(_int)
    # int needs two be two bytes.
    byte0 = _int >> 8
    byte1 = _int - (byte0 << 8)
    _bytearray[byte_index] = byte0
    _bytearray[byte_index + 1] = byte1


def get_int(_bytearray, byte_index):
    """
    Get int value from bytearray.

    int are represented in two bytes
    """
    byte1 = _bytearray[byte_index + 1]
    byte0 = _bytearray[byte_index]
    return byte1 + (byte0 << 8)


def set_real(_bytearray, byte_index, real):
    """
    Set Real value

    make 4 byte data from real

    """
    real = float(real)
    real = struct.pack('>f', real)
    _bytes = struct.unpack('4B', real)
    for i, b in enumerate(_bytes):
        _bytearray[byte_index + i] = b


def get_real(_bytearray, byte_index):
    """
    Get real value. create float from 4 bytes
    """
    x = _bytearray[byte_index:byte_index + 4]
    real = struct.unpack('>f', struct.pack('4B', *x))[0]
    return real


def set_string(_bytearray, byte_index, value, max_size):
    """
    Set string value

    :params value: string data
    :params max_size: max possible string size
    """
    if six.PY2:
        assert isinstance(value, (str, unicode))
    else:
        assert isinstance(value, str)

    size = len(value)
    # FAIL HARD WHEN trying to write too much data into PLC
    if size > max_size:
        raise ValueError('size %s > max_size %s %s' % (size, max_size, value))
    # set len count on first position
    _bytearray[byte_index + 1] = len(value)

    i = 0
    # fill array which chr integers
    for i, c in enumerate(value):
        _bytearray[byte_index + 2 + i] = ord(c)

    # fill the rest with empty space
    for r in range(i + 1, _bytearray[byte_index]):
        _bytearray[byte_index + 2 + r] = ord(' ')


def get_string(_bytearray, byte_index, max_size):
    """
    parse string from bytearray
    """
    size = _bytearray[byte_index + 1]

    if max_size < size:
        logging.error("the string is to big for the size encountered in specification")
        logging.error("WRONG SIZED STRING ENCOUNTERED")
        size = max_size

    data = map(chr, _bytearray[byte_index + 2:byte_index + 2 + size])
    return "".join(data)


def get_dword(_bytearray, byte_index):
    data = _bytearray[byte_index:byte_index + 4]
    dword = struct.unpack('>I', struct.pack('4B', *data))[0]
    return dword


def set_dword(_bytearray, byte_index, dword):
    dword = int(dword)
    _bytes = struct.unpack('4B', struct.pack('>I', dword))
    for i, b in enumerate(_bytes):
        _bytearray[byte_index + i] = b


def parse_specification(db_specification):
    """
    Create a db specification derived from a
    dataview of a db in which the byte layout
    is specified
    """
    parsed_db_specification = OrderedDict()

    for line in db_specification.split('\n'):
        if line and not line.startswith('#'):
            row = line.split('#')[0]  # remove trailing comment
            index, var_name, _type = row.split()
            parsed_db_specification[var_name] = (index, _type)

    return parsed_db_specification


class DB(object):
    """
    Manage a DB bytearray block given a specification
    of the Layout.

    It is possible to have many repetitive instances of
    a specification this is called a "row".

    probably most usecases there is just one row

    db1[0]['testbool1'] = test
    db1.write()   # puts data in plc
    """
    _bytearray = None      # data from plc
    specification = None   # layout of db rows
    row_size = None        # bytes size of a db row
    layout_offset = None   # at which byte in row specification should
                           # we start reading the data
    db_offset = None       # at which byte in db should we start reading?
                           # first fields could be be status data.
                           # and only the last part could be control data
                           # now you can be sure you will never overwrite
                           # critical parts of db

    def __init__(self, db_number, _bytearray,
                 specification, row_size, size, id_field=None,
                 db_offset=0, layout_offset=0, row_offset=0):

        self.db_number = db_number
        self.size = size
        self.row_size = row_size
        self.id_field = id_field

        self.db_offset = db_offset
        self.layout_offset = layout_offset
        self.row_offset = row_offset

        self._bytearray = _bytearray
        self.specification = specification
        # loop over bytearray. make rowObjects
        # store index of id_field to row objects
        self.index = OrderedDict()
        self.make_rows()

    def make_rows(self):
        id_field = self.id_field
        row_size = self.row_size
        specification = self.specification
        layout_offset = self.layout_offset

        for i in range(self.size):
            # calculate where row in bytearray starts
            db_offset = i * row_size + self.db_offset
            # create a row object
            row = DB_Row(self,
                         specification,
                         row_size=row_size,
                         db_offset=db_offset,
                         layout_offset=layout_offset,
                         row_offset=self.row_offset)

            # store row object
            key = row[id_field] if id_field else i
            if key and key in self.index:
                msg = '%s not unique!' % key
                logging.error(msg)
            self.index[key] = row

    def __getitem__(self, key, default=None):
        return self.index.get(key, default)

    def __iter__(self):
        for key, row in self.index.items():
            yield key, row

    def __len__(self):
        return len(self.index)

    def set_data(self, _bytearray):
        assert(isinstance(_bytearray, bytearray))
        self._bytearray = _bytearray


class DB_Row(object):
    """
    Provide ROW API for DB bytearray
    """
    _bytearray = None      # data of reference to parent DB
    _specification = None  # row specification

    def __init__(self, _bytearray, _specification, row_size=0,
                 db_offset=0, layout_offset=0, row_offset=0):

        self.db_offset = db_offset          # start point of row data in db
        self.layout_offset = layout_offset  # start point of row data in layout
        self.row_size = row_size
        self.row_offset = row_offset        # start of writable part of row

        assert(isinstance(_bytearray, (bytearray, DB)))
        self._bytearray = _bytearray
        self._specification = parse_specification(_specification)

    def get_bytearray(self):
        """
        return bytearray from self or DB parent
        """
        if isinstance(self._bytearray, DB):
            return self._bytearray._bytearray
        return self._bytearray

    def export(self):
        """
        export dictionary with values
        """
        data = {}
        for key in self._specification:
            data[key] = self[key]
        return data

    def __getitem__(self, key):
        """
        Get a specific db field
        """
        assert key in self._specification
        index, _type = self._specification[key]
        return self.get_value(index, _type)

    def __setitem__(self, key, value):
        assert key in self._specification
        index, _type = self._specification[key]
        self.set_value(index, _type, value)

    def __repr__(self):

        string = ""
        for var_name, (index, _type) in self._specification.items():
            string = '%s\n%-20s %-10s' % (string, var_name,
                                          self.get_value(index, _type))
        return string

    def unchanged(self, _bytearray):
        if self.get_bytearray() == _bytearray:
            return True
        return False

    def get_offset(self, byte_index):
        """
        Calculate correct beginning position for a row
        the db_offset = row_size * index
        """
        return int(byte_index) - self.layout_offset + self.db_offset

    def get_value(self, byte_index, _type):
        _bytearray = self.get_bytearray()

        if _type == 'BOOL':
            byte_index, bool_index = byte_index.split('.')
            return get_bool(_bytearray, self.get_offset(byte_index),
                            int(bool_index))

        # remove 4 from byte index since
        # first 4 bytes are used by db
        byte_index = self.get_offset(byte_index)

        if _type.startswith('STRING'):
            max_size = re.search('\d+', _type).group(0)
            max_size = int(max_size)
            return get_string(_bytearray, byte_index, max_size)

        if _type == 'REAL':
            return get_real(_bytearray, byte_index)

        if _type == 'DWORD':
            return get_dword(_bytearray, byte_index)

        if _type == 'INT':
            return get_int(_bytearray, byte_index)

        raise ValueError

    def set_value(self, byte_index, _type, value):
        _bytearray = self.get_bytearray()

        if _type == 'BOOL':
            byte_index, bool_index = byte_index.split('.')
            return set_bool(_bytearray, self.get_offset(byte_index),
                            int(bool_index), value)

        byte_index = self.get_offset(byte_index)

        if _type.startswith('STRING'):
            max_size = re.search('\d+', _type).group(0)
            max_size = int(max_size)
            return set_string(_bytearray, byte_index, value, max_size)

        if _type == 'REAL':
            return set_real(_bytearray, byte_index, value)

        if _type == 'DWORD':
            return set_dword(_bytearray, byte_index, value)

        if _type == 'INT':
            return set_int(_bytearray, byte_index, value)

        raise ValueError

    def write(self, client):
        """
        Write current data to db in plc
        """
        assert(isinstance(self._bytearray, DB))
        assert(self.row_size >= 0)

        db_nr = self._bytearray.db_number
        offset = self.db_offset
        data = self.get_bytearray()[offset:offset+self.row_size]
        db_offset = self.db_offset

        # indicate start of write only area of row!
        if self.row_offset:
            data = data[self.row_offset:]
            db_offset += self.row_offset

        client.db_write(db_nr, db_offset, data)

    def read(self, client):
        """
        read current data of db row from plc
        """
        assert(isinstance(self._bytearray, DB))
        assert(self.row_size >= 0)
        db_nr = self._bytearray.db_number
        _bytearray = client.db_read(db_nr, self.db_offset, self.row_size)

        data = self.get_bytearray()
        # replace data in bytearray
        for i, b in enumerate(_bytearray):
            data[i + self.db_offset] = b
