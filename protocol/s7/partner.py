"""
Snap7 code for partnering with a siemens 7 server.

This allows you to create a S7 peer to peer communication. Unlike the
client-server model, where the client makes a request and the server replies to
it, the peer to peer model sees two components with same rights, each of them
can send data asynchronously. The only difference between them is the one who
is requesting the connection.
"""
import ctypes
import logging
import re
from snap7.common import load_library, check_error, ipv4
import snap7.snap7types
from snap7.snap7exceptions import Snap7Exception

logger = logging.getLogger(__name__)


def error_wrap(func):
    """Parses a s7 error code returned the decorated function."""
    def f(*args, **kw):
        code = func(*args, **kw)
        check_error(code, context="partner")
    return f


class Partner(object):
    """
    A snap7 partner.
    """
    def __init__(self, active=False):
        self.library = load_library()
        self.pointer = None
        self.create(active)

    def as_b_send(self):
        """
        Sends a data packet to the partner. This function is asynchronous, i.e.
        it terminates immediately, a completion method is needed to know when
        the transfer is complete.
        """
        return self.library.Par_AsBSend(self.pointer)

    def b_recv(self):
        """
        Receives a data packet from the partner. This function is
        synchronous, it waits until a packet is received or the timeout
        supplied expires.
        """
        return self.library.Par_BRecv(self.pointer)

    def b_send(self):
        """
        Sends a data packet to the partner. This function is synchronous, i.e.
        it terminates when the transfer job (send+ack) is complete.
        """
        return self.library.Par_BSend(self.pointer)

    def check_as_b_recv_completion(self):
        """
        Checks if a packed received was received.
        """
        return self.library.Par_CheckAsBRecvCompletion(self.pointer)

    def check_as_b_send_completion(self):
        """
        Checks if the current asynchronous send job was completed and terminates
        immediately.
        """
        op_result = ctypes.c_int32()
        result = self.library.Par_CheckAsBSendCompletion(self.pointer,
                                                 ctypes.byref(op_result))
        return_values = {
            0: "job complete",
            1: "job in progress",
            -2: "invalid handled supplied",
        }

        if result == -2:
            raise Snap7Exception("The Client parameter was invalid")

        return return_values[result], op_result

    def create(self, active=False):
        """
        Creates a Partner and returns its handle, which is the reference that
        you have to use every time you refer to that Partner.

        :param active: 0
        :returns: a pointer to the partner object
        """
        self.library.Par_Create.restype = snap7.snap7types.S7Object
        self.pointer = snap7.snap7types.S7Object(self.library.Par_Create(int(active)))

    def destroy(self):
        """
        Destroy a Partner of given handle.
        Before destruction the Partner is stopped, all clients disconnected and
        all shared memory blocks released.
        """
        return self.library.Par_Destroy(ctypes.byref(self.pointer))

    def get_last_error(self):
        """
        Returns the last job result.
        """
        error = ctypes.c_int32()
        result = self.library.Par_GetLastError(self.pointer, ctypes.byref(error))
        check_error(result, "partner")
        return error

    def get_param(self, number):
        """
        Reads an internal Partner object parameter.
        """
        logger.debug("retreiving param number %s" % number)
        type_ = snap7.snap7types.param_types[number]
        value = type_()
        code = self.library.Par_GetParam(self.pointer, ctypes.c_int(number),
                                         ctypes.byref(value))
        check_error(code)
        return value.value

    def get_stats(self):
        """
        Returns some statistics.

        :returns: a tuple containing bytes send, received, send errors, recv errors
        """
        sent = ctypes.c_uint32()
        recv = ctypes.c_uint32()
        send_errors = ctypes.c_uint32()
        recv_errors = ctypes.c_uint32()
        result = self.library.Par_GetStats(self.pointer, ctypes.byref(sent),
                                   ctypes.byref(recv),
                                   ctypes.byref(send_errors),
                                   ctypes.byref(recv_errors))
        check_error(result, "partner")
        return sent, recv, send_errors, recv_errors

    def get_status(self):
        """
        Returns the Partner status.
        """
        status = ctypes.c_int32()
        result = self.library.Par_GetStatus(self.pointer, ctypes.byref(status))
        check_error(result, "partner")
        return status

    def get_times(self):
        """
        Returns the last send and recv jobs execution time in milliseconds.
        """
        send_time = ctypes.c_int32()
        recv_time = ctypes.c_int32()
        result = self.library.Par_GetTimes(self.pointer, ctypes.byref(send_time),
                                   ctypes.byref(recv_time))
        check_error(result, "partner")
        return send_time, recv_time

    @error_wrap
    def set_param(self, number, value):
        """Sets an internal Partner object parameter.
        """
        logger.debug("setting param number %s to %s" % (number, value))
        return self.library.Par_SetParam(self.pointer, number,
                                         ctypes.byref(ctypes.c_int(value)))

    def set_recv_callback(self):
        """
        Sets the user callback that the Partner object has to call when a data
        packet is incoming.
        """
        return self.library.Par_SetRecvCallback(self.pointer)

    def set_send_callback(self):
        """
        Sets the user callback that the Partner object has to call when the
        asynchronous data sent is complete.
        """
        return self.library.Par_SetSendCallback(self.pointer)

    @error_wrap
    def start(self):
        """
        Starts the Partner and binds it to the specified IP address and the
        IsoTCP port.
        """
        return self.library.Par_Start(self.pointer)

    @error_wrap
    def start_to(self, local_ip, remote_ip, local_tsap, remote_tsap):
        """
        Starts the Partner and binds it to the specified IP address and the
        IsoTCP port.

        :param local_ip: PC host IPV4 Address. "0.0.0.0" is the default adapter
        :param remote_ip: PLC IPV4 Address
        :param local_tsap: Local TSAP
        :param remote_tsap: PLC TSAP
        """
        assert re.match(ipv4, local_ip), '%s is invalid ipv4' % local_ip
        assert re.match(ipv4, remote_ip), '%s is invalid ipv4' % remote_ip
        logger.info("starting partnering from %s to %s" % (local_ip, remote_ip))
        return self.library.Par_StartTo(self.pointer, local_ip, remote_ip,
                                        ctypes.c_uint16(local_tsap),
                                        ctypes.c_uint16(remote_tsap))

    def stop(self):
        """
        Stops the Partner, disconnects gracefully the remote partner.
        """
        return self.library.Par_Stop(self.pointer)

    @error_wrap
    def wait_as_b_send_completion(self, timeout=0):
        """
        Waits until the current asynchronous send job is done or the timeout
        expires.
        """
        return self.library.Par_WaitAsBSendCompletion(self.pointer, timeout)
