""" logger.py
This module is used for logging details of the lifting instruction.
"""
import os
from datetime import datetime
import logging


ENABLE_LOGGING = False  # True/False to enable/disable logging
LOGFILES_PATH = "{0}/logs/".format(os.path.expanduser("~"))
LOGFILE = "{0}/log_{1}.log".format(LOGFILES_PATH, datetime.now().date())

if ENABLE_LOGGING:
    if not os.path.exists(LOGFILES_PATH):
        os.mkdir(LOGFILES_PATH)

    if os.path.exists(LOGFILE):
        os.remove(LOGFILE)

    fh = logging.FileHandler(LOGFILE)
    pyvexlog = logging.getLogger('pyvex')
    pyvexlog.setLevel(logging.DEBUG)
    pyvexlog.addHandler(fh)

def log_this(name, data, addr):
    """ Log instruction details.
        :param name: name of the instruction.
        :param data: details of the instruction.
        :param addr: the calling address.
    """
    if ENABLE_LOGGING:
        pyvexlog.debug("-"*100)
        pyvexlog.debug(name)
        pyvexlog.debug(data)
        pyvexlog.debug("addr: %s", addr)

def log_val(val):
    """ Log any value. """
    if ENABLE_LOGGING:
        pyvexlog.debug(val)
        print(val)  # print to screen
