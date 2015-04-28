#!/usr/bin/env python2.7

import struct
import logging
import utils
from stream import Stream
from amfcommand import AMFCommand, AMFCommands
logger = logging.getLogger(__name__)


class RTMPParser():

    AMF0_COMMAND = 0x14
    AMF3_COMMAND = 0x11

    AMF_STRING = chr(0x02)
    AMF_NUMBER = chr(0x00)
    AMF_OBJECT = chr(0x03)
    AMF_BOOLEAN = chr(0x01)
    AMF_NULL = chr(0x05)
    AMF_ARRAY = chr(0x08)

    chunk_para = {}
    # Record parameter for each chunk stream id so that Type 2 b10 and Type
    # 3 b11 chunks can be processed

    def __init__(self):
        pass

    def rtmp_parse_stream(self, stream):
        """
        Parses the stream packet by packet
        and returns a list containing all the AMFCommand objects found
        """

        cmds = AMFCommands()

        # Looking for the handshakes
        H1 = stream.get_bytes(1)
        H1_rndData = stream.get_bytes(0x600)  # 1536
        H2_rndData = stream.get_bytes(0x600)

        if H1 != chr(0x03) or H1_rndData is None or H2_rndData is None:
            return cmds

        # hexdump(stream.stream)
        # print hex(stream.offset)
        # print '*' * 100
        # stream.dump()
        # print

        while (stream.have_bytes()):
            cmd = self.rtmp_parse_packet(stream)
            if cmd:
                cmds.add(cmd)
        cmds.parse()

        return cmds

    def rtmp_parse_packet(self, stream):
        """Parses the RTMP object at the beginning of the stream.

        The stream pointer is incremented.

        Packet header byte 1
        BB BBBBBB
        The first 2 bit indicates the header type as following:
            b00 = 12 byte header (full header).
            b01 = 8 bytes - like type b00. not including message ID (last 4B).
            b10 = 4 bytes - Basic Header and timestamp (3 bytes) are included.
            b11 = 1 byte - only the Basic Header is included.
        The last 6 bit indicates the chunk stream ID
        """
        byte = stream.get_byte()
        header_type = byte >> 6
        chunk_stream_id = byte - (header_type << 6)

        if chunk_stream_id not in self.chunk_para:
            self.chunk_para[chunk_stream_id] = {}

        # Header type b00
        if header_type == 0:
            utils.str2num(stream.get_bytes(3))  # timestamp
            body_size = utils.str2num(stream.get_bytes(3))
            packet_type = stream.get_byte()
            utils.str2num(stream.get_bytes(4))  # stream_id
            self.chunk_para[chunk_stream_id]['length'] = body_size
            self.chunk_para[chunk_stream_id]['packet_type'] = packet_type

        # Header type b01
        elif header_type == 1:
            utils.str2num(stream.get_bytes(3))  # timestamp
            body_size = utils.str2num(stream.get_bytes(3))
            packet_type = stream.get_byte()
            self.chunk_para[chunk_stream_id]['length'] = body_size
            self.chunk_para[chunk_stream_id]['packet_type'] = packet_type

        # Header type b10
        elif header_type == 2:
            utils.str2num(stream.get_bytes(3))  # timestamp
            if chunk_stream_id not in self.chunk_para:
                stream.offset = stream.size
                return None
            try:
                body_size = self.chunk_para[chunk_stream_id]['length']
                packet_type = self.chunk_para[chunk_stream_id]['packet_type']
            except:
                return None

        # Header type b11
        elif header_type == 3:
            if chunk_stream_id not in self.chunk_para:
                stream.offset = stream.size
                return None
            try:
                body_size = self.chunk_para[chunk_stream_id]['length']
                packet_type = self.chunk_para[chunk_stream_id]['packet_type']
            except:
                return None

        else:
            logger.error("RTMP header type not supported: %d", header_type)
            return None

        # print type(packet_type), packet_type, self.AMF0_COMMAND,
        # self.AMF3_COMMAND

        logger.debug("Start parsing packet with length %d from offset %d",
                     body_size, stream.offset)

        # Read RTMP payload from the stream
        magic_byte = 0xC0 + chunk_stream_id
        magic_bytes_count = body_size / 128
        rtmp_payload = stream.get_bytes(body_size + magic_bytes_count)

        if rtmp_payload is None:
            return None

        # Unchunking the payload
        n = 0
        while (n < len(rtmp_payload)):
            if (n % 128 == 0) and (n != 0):
                if magic_byte < 256 and rtmp_payload[n] == chr(magic_byte):
                    rtmp_payload = rtmp_payload[:n] + rtmp_payload[n + 1:]
                else:
                    logger.debug(
                        "Expected RTMP magic byte %x "
                        "not found in the payload[%d] %s",
                        magic_byte, n, rtmp_payload[n])
                    return None
            n = n + 1

        # Parse the payload - create a new Stream object with only the payload
        # to be passed to the parsing function
        rtmp_payload_stream = Stream(rtmp_payload)
        # hexdump(rtmp_payload)

        # If it's an AMF0/AMF3 command
        if packet_type == self.AMF0_COMMAND or \
                packet_type == self.AMF3_COMMAND:
            cmd = AMFCommand()

            # rtmp_payload_stream.dump()

            # In case of AMF3 command, there is an extra byte at the beginning
            # of the body
            if packet_type == self.AMF3_COMMAND:
                rtmp_payload_stream.get_byte()

            """
            The structure of the RTMP Command is:
                (String) <Command Name>
                (Number) <Transaction Id>
                (Mixed)  <Argument> ex. Null, String, Object: {
                    key1:value1, key2:value2 ... }
            """

            # Reading AMF Command
            cmd.name = self.rtmp_parse_object(rtmp_payload_stream)

            # Interested only in "connect" and "play" objects
            if cmd.name not in ["connect", "play"]:
                logger.debug("Skip irrelative command: %s", cmd.name)
                return None

            # Read AMF Transaction ID
            cmd.transaction_id = self.rtmp_parse_object(rtmp_payload_stream)

            # Read all the AMF arguments
            while rtmp_payload_stream.have_bytes():
                cmd.args.append(self.rtmp_parse_object(rtmp_payload_stream))

            return cmd

        # Discard otherwise
        else:
            logger.debug("Skip irrelative packet type: %s", packet_type)

        return None

    def rtmp_parse_object(self, p):
        ''' Parse a single RTMP object '''

        # Object type
        b = p.get_bytes(1)

        # STRING
        if b == self.AMF_STRING:
            strlen = utils.str2num(p.get_bytes(2))
            string = p.get_bytes(strlen)
            logger.debug("Found a string [%s]..." % string)
            return string

        # NUMBER
        # Numbers are stored as 8 byte (big endian) float double
        elif b == self.AMF_NUMBER:
            number = struct.unpack('>d', p.get_bytes(8))
            logger.debug("Found a number [%d]..." % number)
            return int(number[0])

        # BOOLEAN
        elif b == self.AMF_BOOLEAN:
            boolean = False if (p.get_bytes(1) == chr(0)) else True
            logger.debug("Found a boolean (%s)..." % boolean)
            return boolean

        # OBJECT
        elif b == self.AMF_OBJECT:
            logger.debug("Found an object...")
            obj = dict()

            # Reading all the object properties, until End Of Object marker is
            # reached
            while (p.read_bytes(3) != "\x00\x00\x09"):

                # Property name
                strlen = utils.str2num(p.get_bytes(2))
                key = p.get_bytes(strlen)
                logger.debug("Property name [%s]...", key)

                # Property value
                val = self.rtmp_parse_object(p)

                obj[key] = val

            # Eating the End Of Object marker
            p.get_bytes(3)

            return obj

        # NULL
        elif b == self.AMF_NULL:
            logger.debug("Found a NULL byte...")
            return None

        # ARRAY
        # don't care
        elif b == self.AMF_ARRAY:
            utils.str2num(p.get_bytes(4))  # arraylen
            logger.debug("Found an array...")
            while p.read_bytes(3) != "\x00\x00\x09":
                pass
            p.get_bytes(3)
            return 0

        # Unknown object
        else:
            logger.error("Found an unknown RTMP object: 0x%x", ord(b))
            return None
