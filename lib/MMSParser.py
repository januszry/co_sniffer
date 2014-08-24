#!/usr/bin/env python2.7

import traceback
import logging
import Utils
from MMSCommand import MMSCommand
logger = logging.getLogger(__name__)


class MMSParser(object):
    '''
    Little Endian
    Convert Method: str[::-1]

    MMS Commmand Packet Structure:
    +-------------+-------------+-------------+-------------+
    | 01 00 00 00 | -- -- -- -- | -- -- -- -- | -- -- -- -- |
    | START SIGN  |  SIGNATURE  | CMD LENGTH  | PROTO TYPE  |  CMD_LENGTH is calculated from start of next line
    +-------------+-------------+-------------+-------------+
    | -- -- -- -- | -- -- -- -- | -- -- -- --   -- -- -- -- |
    | LEN to END  | SEQ NUMBER  |         TIME STAMP        |  LEN_TO_END is number of 8Bytes till end
    +-------------+-------------+-------------+-------------+
    | -- -- -- -- | -- --|-- -- | -- -- -- -- | -- -- -- -- |
    | LEN to END  |  CMD | DIRE |   PREFIX 1  |   PREFIX 2  |  DIRE is MMS_DIRECTION
    +-------------+-------------+-------------+-------------+
    | -- ...                                                |
    | DATA                                                  |
    +-------------+-------------+-------------+-------------+
    | -- ...      | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 |
    | DATA        |                 PADDING                 |  PADDING to times of 8Bytes
    +-------------+-------------+-------------+-------------+

    '''

    MMS_COMMAND_START = '\x00\x00\x00\x01'
    MMS_PROTO = 'MMS '

    MMS_DIRECTION_TO_SERVER = '\x00\x03'
    MMS_COMMAND_CONNECT_INFO = '\x00\x01'
    MMS_COMMAND_TIMING_TEST_DATA_REQUEST = '\x00\x18'
    MMS_COMMAND_TRANSPORT_INFO = '\x00\x02'
    MMS_COMMAND_REQUEST_SERVER_FILE = '\x00\x05'
    MMS_COMMAND_HEADER_REQUEST = '\x00\x15'
    MMS_COMMAND_START_SENDING_FROM = '\x00\x07'
    MMS_COMMAND_CANCEL_PROTOCOL = '\x00\x0d'

    MMS_DIRECTION_TO_CLIENT = '\x00\x04'
    MMS_COMMAND_SERVER_INFO = '\x00\x01'
    MMS_COMMAND_TIMING_TEST_DATA_RESPONSE = '\x00\x15'
    MMS_COMMAND_TRANSPORT_ACK = '\x00\x02'
    MMS_COMMAND_MEDIA_DETAILS = '\x00\x06'
    MMS_COMMAND_HEADER_RESPONSE = '\x00\x11'
    MMS_COMMAND_STREAM_SELECTION_INDICATOR = '\x00\x21'
    MMS_COMMAND_SENDING_MEDIA_FILE_NOW = '\x00\x05'

    MMS_ERROR_CODE_OK = '\x00\x00\x00\x00'

    def __init__(self):
        pass

    def mms_parse_packet(self, packet):
        """
        Parses the MMS packet
        """

        # packet.dump()
        start = packet.get_bytes(4)[::-1]
        signature = packet.get_bytes(4)[::-1]
        cmd_length = Utils.str2num(packet.get_bytes(4)[::-1])
        proto_type = packet.get_bytes(4)

        if start != self.MMS_COMMAND_START or proto_type != self.MMS_PROTO:
            return None

        packet.get_bytes(4)  # skip first LEN_to_END
        seq_number = Utils.str2num(packet.get_bytes(4)[::-1])
        timestamp = Utils.str2num(packet.get_bytes(8)[::-1])

        packet.get_bytes(4)  # skip second LEN_to_END
        mms_cmd_type = packet.get_bytes(2)[::-1]
        mms_direction = packet.get_bytes(2)[::-1]
        logger.debug("Got command %s in direction %s", repr(
            mms_cmd_type), repr(mms_direction))

        # Only care about connect info and request file command sent to server
        if mms_direction != self.MMS_DIRECTION_TO_SERVER or \
                mms_cmd_type not in [
                    self.MMS_COMMAND_CONNECT_INFO, self.MMS_COMMAND_REQUEST_SERVER_FILE]:
            logger.debug("Irrelative command %s in direction %s, skipping",
                         repr(mms_cmd_type), repr(mms_direction))
            return None

        prefix_1 = packet.get_bytes(4)[::-1]
        prefix_2 = packet.get_bytes(4)[::-1]

        if cmd_length <= 32:
            return None

        mms_cmd = MMSCommand()
        data = ''

        if mms_cmd_type == self.MMS_COMMAND_CONNECT_INFO:
            mms_cmd.name = 'connect_info'
            packet.get_bytes(4)    # skip 4 bytes, unknown
            while packet.have_bytes():
                data += unichr(
                    Utils.str2num(packet.get_bytes(2)[::-1])).encode('utf-8')
            data = data.rstrip('\x00')
            data = data.split('; ')
            for i in data:
                if 'Host: ' in i:
                    mms_cmd.args['host'] = i[i.find('Host: ') + 6:]
        elif mms_cmd_type == self.MMS_COMMAND_REQUEST_SERVER_FILE:
            mms_cmd.name = 'request_server_file'
            packet.get_bytes(8)    # skip 8 bytes, usually 8 zeros
            while packet.have_bytes():
                data += unichr(
                    Utils.str2num(packet.get_bytes(2)[::-1])).encode('utf-8')
            mms_cmd.args['server_file'] = data.rstrip('\x00')

        logger.debug("Got data %s", repr(mms_cmd.args))

        return mms_cmd
