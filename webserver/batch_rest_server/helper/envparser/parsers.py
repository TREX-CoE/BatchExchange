__all__ = ["flag", "choices", "exists", "file", "writeable", "creatable", "syslog_address"]

from pathlib import Path
import os
import socket

def flag(s):
    lower = s.lower()
    if lower in ('true', '1', 'yes'):
        return True
    elif lower in ('false', '0', 'no'):
        return False
    raise ValueError("Invalid bool '{}'".format(s))

def choices(*choices, name="value"):
    def p(s):
        if s in choices:
            return s
        else:
            raise ValueError('Invalid {} "{}" has to be one of {}'.format(name, s, ", ".join('"{}"'.format(c) for c in choices)))
    return p

def exists(s):
    if not Path(s).exists(): raise ValueError("'{}' does not exist".format(s))
    return s
def file(s):
    if not Path(s).is_file(): raise ValueError("'{}' is not a file".format(s))
    return s
def writeable(s):
    if not os.access(s, os.W_OK): raise ValueError("'{}' is not writeable".format(s))
    return s
def creatable(s):
    if not os.access(Path(s).parent, os.W_OK): raise ValueError("'{}' is not createable".format(s))
    return s

def syslog_address(addr):
    """Parse syslog address like in gunicorn to options for SysLogHandler.

    Code adapted from gunicorn/glogging.py.
    """

    # unix domain socket type depends on backend
    # SysLogHandler will try both when given None
    if addr.startswith("unix://"):
        socktype = None

        # set socket type only if explicitly requested
        parts = addr.split("#", 1)
        if len(parts) == 2:
            addr = parts[0]
            if parts[1] == "dgram":
                socktype = socket.SOCK_DGRAM

        address = addr.split("unix://")[1]

    else:
        if addr.startswith("udp://"):
            addr = addr.split("udp://")[1]
            socktype = socket.SOCK_DGRAM
        elif addr.startswith("tcp://"):
            addr = addr.split("tcp://")[1]
            socktype = socket.SOCK_STREAM
        else:
            raise ValueError("invalid syslog address")

        if '[' in addr and ']' in addr:
            host = addr.split(']')[0][1:].lower()
        elif ':' in addr:
            host = addr.split(':')[0].lower()
        elif addr == "":
            host = "localhost"
        else:
            host = addr.lower()

        addr = addr.split(']')[-1]
        if ":" in addr:
            port = addr.split(':', 1)[1]
            if not port.isdigit():
                raise ValueError("%r is not a valid port number." % port)
            port = int(port)
        else:
            port = 514

        address = (host, port)

    return dict(address=address, socktype=socktype)
