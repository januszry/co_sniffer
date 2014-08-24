#!/usr/bin/env python2.7

import logging

log_file = r'sniffer.log'
log_format = '[%(levelname)s]<%(module)s>-%(funcName)s: %(message)s --- %(asctime)s'
log_formatter = logging.Formatter(log_format)

logfile_handler = logging.FileHandler(log_file)
logfile_handler.setFormatter(log_formatter)
logstream_handler = logging.StreamHandler()
logstream_handler.setFormatter(log_formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(logfile_handler)
logger.addHandler(logstream_handler)
