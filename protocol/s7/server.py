"""
Snap7 server used for mimicking a siemens 7 server.
"""
import ctypes
import logging
import re
import snap7.snap7types
from snap7.common import check_error, load_library, ipv4
from snap7 import six

logger = logging.getLogger(__name__)


def error_wrap(func):
    """Parses a s7 error code returned the decorated function."""

    def f(*args, **kw):
        code = func(*args, **kw)
        check_error(code, context="server")

    return f


class Server(object):
    """
    A fake S7 server.
    """

    def __init__(self, log=True):
        """
        Create a fake S7 server. set log to false if you want to disable
        event logging to python logging.
        """
        self.pointer = None
        self._callback = None
        self.library = load_library()
        self.create()
        if log:
            self._set_log_callback()

    def event_text(self, event):
        """Returns a textual explanation of a given event object

        :param event: an PSrvEvent struct object
        :returns: the error string
        """
        logger.debug("error text for %s" % hex(event.EvtCode))
        len_ = 1024
        text_type = ctypes.c_char * len_
        text = text_type()
        error = self.library.Srv_EventText(ctypes.byref(event),
                                           ctypes.byref(text), len_)
        check_error(error)
        if six.PY2:
            return text.value
        else:
            return text.value.decode('ascii')

    def create(self):
        """
        create the server.
        """
        logger.info("creating server")
        self.library.Srv_Create.restype = snap7.snap7types.S7Object
        self.pointer = snap7.snap7types.S7Object(self.library.Srv_Create())

    @error_wrap
    def register_area(self, area_code, index, userdata):
        """Shares a memory area with the server. That memory block will be
        visible by the clients.
        """
        size = ctypes.sizeof(userdata)
        logger.info("registering area %s, index %s, size %s" % (area_code,
                                                                index, size))
        size = ctypes.sizeof(userdata)
        return self.library.Srv_RegisterArea(self.pointer, area_code, index,
                                             ctypes.byref(userdata), size)

    @error_wrap
    def set_events_callback(self, call_back):
        """Sets the user callback that the Server object has to call when an
        event is created.
        """
        logger.info("setting event callback")
        callback_wrap = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                                         ctypes.POINTER(snap7.snap7types.SrvEvent),
                                         ctypes.c_int)

        def wrapper(usrptr, pevent, size):
            """
            Wraps python function into a ctypes function

            :param usrptr: not used
            :param pevent: pointer to snap7 event struct
            :param size:
            :returns: should return an int
            """
            logger.info("callback event: " + self.event_text(pevent.contents))
            call_back(pevent.contents)
            return 0

        self._callback = callback_wrap(wrapper)
        usrPtr = ctypes.c_void_p()
        return self.library.Srv_SetEventsCallback(self.pointer, self._callback, usrPtr)

    @error_wrap
    def set_read_events_callback(self, call_back):
        """
        Sets the user callback that the Server object has to call when a Read
        event is created.

        :param call_back: a callback function that accepts a pevent argument.
        """
        logger.info("setting read event callback")
        callback_wrapper = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                                            ctypes.POINTER(snap7.snap7types.SrvEvent),
                                            ctypes.c_int)

        def wrapper(usrptr, pevent, size):
            """
            Wraps python function into a ctypes function

            :param usrptr: not used
            :param pevent: pointer to snap7 event struct
            :param size:
            :returns: should return an int
            """
            logger.info("callback event: " + self.event_text(pevent.contents))
            call_back(pevent.contents)
            return 0

        self._read_callback = callback_wrapper(wrapper)
        return self.library.Srv_SetReadEventsCallback(self.pointer,
                                                      self._read_callback)

    def _set_log_callback(self):
        """Sets a callback that logs the events
        """
        logger.debug("setting up event logger")

        def log_callback(event):
            logger.info("callback event: " + self.event_text(event))

        self.set_events_callback(log_callback)

    @error_wrap
    def start(self, tcpport=102):
        """
        start the server.
        """
        if tcpport != 102:
            logging.info("setting server TCP port to %s" % tcpport)
            self.set_param(snap7.snap7types.LocalPort, tcpport)
        logger.info("starting server on 0.0.0.0:%s" % tcpport)
        return self.library.Srv_Start(self.pointer)

    @error_wrap
    def stop(self):
        """
        stop the server.
        """
        logger.info("stopping server")
        return self.library.Srv_Stop(self.pointer)

    def destroy(self):
        """
        destroy the server.
        """
        logger.info("destroying server")
        self.library.Srv_Destroy(ctypes.byref(self.pointer))

    def get_status(self):
        """Reads the server status, the Virtual CPU status and the number of
        the clients connected.

        :returns: server status, cpu status, client count
        """
        logger.debug("get server status")
        server_status = ctypes.c_int()
        cpu_status = ctypes.c_int()
        clients_count = ctypes.c_int()
        error = self.library.Srv_GetStatus(self.pointer, ctypes.byref(server_status),
                                           ctypes.byref(cpu_status),
                                           ctypes.byref(clients_count))
        check_error(error)
        logger.debug("status server %s cpu %s clients %s" %
                     (server_status.value, cpu_status.value,
                      clients_count.value))
        return snap7.snap7types.server_statuses[server_status.value], \
               snap7.snap7types.cpu_statuses[cpu_status.value], \
               clients_count.value

    @error_wrap
    def unregister_area(self, area_code, index):
        """'Unshares' a memory area previously shared with Srv_RegisterArea().
        That memory block will be no longer visible by the clients.
        """
        return self.library.Srv_UnregisterArea(self.pointer, area_code, index)

    @error_wrap
    def unlock_area(self, code, index):
        """Unlocks a previously locked shared memory area.
        """
        logging.debug("unlocking area code %s index %s" % (code, index))
        return self.library.Srv_UnlockArea(self.pointer, code, index)

    @error_wrap
    def lock_area(self, code, index):
        """Locks a shared memory area.
        """
        logging.debug("locking area code %s index %s" % (code, index))
        return self.library.Srv_UnlockArea(self.pointer, code, index)

    @error_wrap
    def start_to(self, ip, tcpport=102):
        """
        start server on a specific interface.
        """
        if tcpport != 102:
            logging.info("setting server TCP port to %s" % tcpport)
            self.set_param(snap7.snap7types.LocalPort, tcpport)
        assert re.match(ipv4, ip), '%s is invalid ipv4' % ip
        logger.info("starting server to %s:102" % ip)
        return self.library.Srv_Start(self.pointer, ip)

    @error_wrap
    def set_param(self, number, value):
        """Sets an internal Server object parameter.
        """
        logger.debug("setting param number %s to %s" % (number, value))
        return self.library.Srv_SetParam(self.pointer, number,
                                         ctypes.byref(ctypes.c_int(value)))

    @error_wrap
    def set_mask(self, kind, mask):
        """Writes the specified filter mask.
        """
        logger.debug("setting mask kind %s to %s" % (kind, mask))
        return self.library.Srv_SetMask(self.pointer, kind, mask)

    @error_wrap
    def set_cpu_status(self, status):
        """Sets the Virtual CPU status.
        """
        assert status in snap7.snap7types.cpu_statuses, 'unknown cpu state %s' % status
        logger.debug("setting cpu status to %s" % status)
        return self.library.Srv_SetCpuStatus(self.pointer, status)

    def pick_event(self):
        """Extracts an event (if available) from the Events queue.
        """
        logger.debug("checking event queue")
        event = snap7.snap7types.SrvEvent()
        ready = ctypes.c_int32()
        code = self.library.Srv_PickEvent(self.pointer, ctypes.byref(event),
                                          ctypes.byref(ready))
        check_error(code)
        if ready:
            logger.debug("one event ready: %s" % event)
            return event
        logger.debug("no events ready")

    def get_param(self, number):
        """Reads an internal Server object parameter.
        """
        logger.debug("retreiving param number %s" % number)
        value = ctypes.c_int()
        code = self.library.Srv_GetParam(self.pointer, number,
                                         ctypes.byref(value))
        check_error(code)
        return value.value

    def get_mask(self, kind):
        """Reads the specified filter mask.
        """
        logger.debug("retrieving mask kind %s" % kind)
        mask = snap7.snap7types.longword()
        code = self.library.Srv_GetMask(self.pointer, kind, ctypes.byref(mask))
        check_error(code)
        return mask

    @error_wrap
    def clear_events(self):
        """Empties the Event queue.
        """
        logger.debug("clearing event queue")
        return self.library.Srv_ClearEvents(self.pointer)
