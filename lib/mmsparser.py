import logging

from .utils import str2num, convert_bytes_to_str, bytechr
from .mmscommand import MMSCommand


class MMSParser(object):

    """Parser for MMS Command.

    Little Endian
    Convert Method: str[::-1]

    MMS Commmand Packet Structure:
    +-------------+-------------+-------------+-------------+
    | 01 00 00 00 | -- -- -- -- | -- -- -- -- | -- -- -- -- |
    | START SIGN  |  SIGNATURE  | CMD LENGTH  | PROTO TYPE  |
    +-------------+-------------+-------------+-------------+
    | -- -- -- -- | -- -- -- -- | -- -- -- --   -- -- -- -- |
    | LEN to END  | SEQ NUMBER  |         TIME STAMP        |
    +-------------+-------------+-------------+-------------+
    | -- -- -- -- | -- --|-- -- | -- -- -- -- | -- -- -- -- |
    | LEN to END  |  CMD | DIRE |   PREFIX 1  |   PREFIX 2  |
    +-------------+-------------+-------------+-------------+
    | -- ...                                                |
    | DATA                                                  |
    +-------------+-------------+-------------+-------------+
    | -- ...      | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 |
    | DATA        |                 PADDING                 |
    +-------------+-------------+-------------+-------------+

    CMD_LENGTH is calculated from start of next line
    LEN_TO_END is number of 8Bytes till end
    DIRE is MMS_DIRECTION
    PADDING to times of 8Bytes"""

    MMS_COMMAND_START = b'\x00\x00\x00\x01'
    MMS_PROTO = 'MMS '

    MMS_DIRECTION_TO_SERVER = b'\x00\x03'
    MMS_COMMAND_CONNECT_INFO = b'\x00\x01'
    MMS_COMMAND_TIMING_TEST_DATA_REQUEST = b'\x00\x18'
    MMS_COMMAND_TRANSPORT_INFO = b'\x00\x02'
    MMS_COMMAND_REQUEST_SERVER_FILE = b'\x00\x05'
    MMS_COMMAND_HEADER_REQUEST = b'\x00\x15'
    MMS_COMMAND_START_SENDING_FROM = b'\x00\x07'
    MMS_COMMAND_CANCEL_PROTOCOL = b'\x00\x0d'

    MMS_DIRECTION_TO_CLIENT = b'\x00\x04'
    MMS_COMMAND_SERVER_INFO = b'\x00\x01'
    MMS_COMMAND_TIMING_TEST_DATA_RESPONSE = b'\x00\x15'
    MMS_COMMAND_TRANSPORT_ACK = b'\x00\x02'
    MMS_COMMAND_MEDIA_DETAILS = b'\x00\x06'
    MMS_COMMAND_HEADER_RESPONSE = b'\x00\x11'
    MMS_COMMAND_STREAM_SELECTION_INDICATOR = b'\x00\x21'
    MMS_COMMAND_SENDING_MEDIA_FILE_NOW = b'\x00\x05'

    MMS_ERROR_CODE_OK = b'\x00\x00\x00\x00'

    def __init__(self):
        self._logger = logging.getLogger(__name__)

    def mms_parse_packet(self, packet):
        """Parses the MMS packet."""

        # packet.dump()
        start = packet.get_bytes(4)[::-1]

        packet.get_bytes(4)  # skip SIGNATURE

        cmd_length = str2num(packet.get_bytes(4)[::-1])
        proto_type = convert_bytes_to_str(packet.get_bytes(4))

        if start != self.MMS_COMMAND_START or proto_type != self.MMS_PROTO:
            return None

        packet.get_bytes(4)  # skip first LEN_to_END
        packet.get_bytes(4)  # skip SEQ NUMBER
        packet.get_bytes(8)  # skip PROTO TYPE
        packet.get_bytes(4)  # skip second LEN_to_END
        mms_cmd_type = packet.get_bytes(2)[::-1]
        mms_direction = packet.get_bytes(2)[::-1]
        self._logger.debug("Got command %s in direction %s", repr(
            mms_cmd_type), repr(mms_direction))

        # Only care about connect info and request file command sent to server
        if mms_direction != self.MMS_DIRECTION_TO_SERVER or \
                mms_cmd_type not in [
                    self.MMS_COMMAND_CONNECT_INFO,
                    self.MMS_COMMAND_REQUEST_SERVER_FILE]:
            self._logger.debug(
                "Irrelative command %s in direction %s, skipping",
                repr(mms_cmd_type), repr(mms_direction))
            return None

        if cmd_length <= 32:
            return None

        mms_cmd = MMSCommand()
        data = b''

        if mms_cmd_type == self.MMS_COMMAND_CONNECT_INFO:
            mms_cmd.name = 'connect_info'
            packet.get_bytes(4)    # skip 4 bytes, unknown
            while packet.have_bytes():
                tmp = str2num(packet.get_bytes(2)[::-1])
                data += bytechr(tmp)
            data = data.rstrip(b'\x00')
            data = data.split(b'; ')
            for i in data:
                if b'Host: ' in i:
                    mms_cmd.args['host'] = convert_bytes_to_str(
                        i[i.find(b'Host: ') + 6:])
        elif mms_cmd_type == self.MMS_COMMAND_REQUEST_SERVER_FILE:
            mms_cmd.name = 'request_server_file'
            packet.get_bytes(8)    # skip 8 bytes, usually 8 zeros
            while packet.have_bytes():
                tmp = str2num(packet.get_bytes(2)[::-1])
                data += bytechr(tmp)
            mms_cmd.args['server_file'] = convert_bytes_to_str(
                data.rstrip(b'\x00'))

        self._logger.debug("Got data %s", repr(mms_cmd.args))

        return mms_cmd
