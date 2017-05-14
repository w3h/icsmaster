from ctypes import c_char
from ctypes.util import find_library
import logging
from snap7.snap7exceptions import Snap7Exception
import sys,os
import platform

import platform
if platform.system() == 'Windows':
    from ctypes import windll as cdll
else:
    from ctypes import cdll


logger = logging.getLogger(__name__)

# regexp for checking if an ipv4 address is valid.
ipv4 = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"


def GetSnap7Dll():
    cur_file_dir = os.path.split(os.path.realpath(__file__))[0]
    platbit,plat = platform.architecture()
    if "Windows" in plat:
        if '32' in platbit:
            return os.path.join(cur_file_dir, 'lib\\Windows\\Win32\\snap7.dll')
        elif '64' in platbit:
            return os.path.join(cur_file_dir, 'lib\\Windows\\Win64\\snap7.dll')

class ADict(dict):
    """
    Accessing dict keys like an attribute.
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__


class Snap7Library(object):
    """
    Snap7 loader and encapsulator. We make this a singleton to make
    sure the library is loaded only once.
    """
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = object.__new__(cls)
            cls._instance.lib_location = None
            cls._instance.cdll = None
        return cls._instance

    def __init__(self, lib_location=None):
        if self.cdll:
            return
        self.lib_location = lib_location or self.lib_location or find_library('snap7')
        if not self.lib_location:
            msg = "can't find snap7 library. If installed, try running ldconfig"
            self.lib_location = GetSnap7Dll()
            print self.lib_location
            #print self.lib_location
            if not os.path.isfile(self.lib_location):
                raise Snap7Exception(msg)
        self.cdll = cdll.LoadLibrary(self.lib_location)


def load_library(lib_location=None):
    """
    :returns: a ctypes cdll object with the snap7 shared library loaded.
    """
    return Snap7Library(lib_location).cdll


def check_error(code, context="client"):
    """
    check if the error code is set. If so, a Python log message is generated
    and an error is raised.
    """
    if code:
        error = error_text(code, context)
        logger.error(error)
        raise Snap7Exception(error)


def error_text(error, context="client"):
    """Returns a textual explanation of a given error number

    :param error: an error integer
    :param context: server, client or partner
    :returns: the error string
    """
    assert context in ("client", "server", "partner")
    logger.debug("error text for %s" % hex(error))
    len_ = 1024
    text_type = c_char * len_
    text = text_type()
    library = load_library()
    if context == "client":
        library.Cli_ErrorText(error, text, len_)
    elif context == "server":
        library.Srv_ErrorText(error, text, len_)
    elif context == "partner":
        library.Par_ErrorText(error, text, len_)
    return text.value
