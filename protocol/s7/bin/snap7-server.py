#!/usr/bin/env python
"""
This is an example snap7 server. It doesn't do much, but accepts
connection. Useful for running the python-snap7 test suite.
"""
import time
import logging
import snap7
import sys


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

tcpport = 1102


def mainloop():
    server = snap7.server.Server()
    size = 100
    data = (snap7.snap7types.wordlen_to_ctypes[snap7.snap7types.S7WLByte] * size)()
    server.register_area(snap7.snap7types.srvAreaDB, 1, data)

    server.start(tcpport=tcpport)
    while True:
        while True:
            event = server.pick_event()
            if event:
                logger.info(server.event_text(event))
            else:
                break
        time.sleep(1)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        snap7.common.load_library(sys.argv[1])
    mainloop()
