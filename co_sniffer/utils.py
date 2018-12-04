import logging


def config_logger(logger):
    logstream_handler = logging.StreamHandler()
    log_formatter = logging.Formatter(
        '[%(levelname)s]<%(module)s>-%(funcName)s: %(message)s -- %(asctime)s')

    logstream_handler.setFormatter(log_formatter)
    logstream_handler.setLevel(logging.DEBUG)
    logger.addHandler(logstream_handler)

    logger.setLevel(logging.INFO)
