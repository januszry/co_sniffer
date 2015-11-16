#!/usr/bin/env python3

import os
import logging
import argparse
import traceback
import time
import pickle
import socket

import netifaces
from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from scapy.sendrecv import sniff as _sniff

from .lib.stream import Stream, StreamNoMoreBytes
from .lib.rtmpparser import RTMPParser
from .lib.mmsparser import MMSParser
from .lib.mmscommand import MMSCommands
from .lib.wmspparser import WMSPParser
from .lib.wmspcommand import WMSPCommands
from .lib.rtspparser import RTSPParser
from .lib.rtspcommand import RTSPCommands
from .lib.httpparser import HTTPParser
from .lib.httpcommand import HTTPCommands


all_devices = {}
sessions = {}
# Session here is different from session in RFC: Only one direction, i.e.
# A -> B and B -> A are 2 sessions

SNIFF_RTMP = True
SNIFF_MMSP = True
SNIFF_WMSP = True
SNIFF_RTSP = True
SNIFF_HTTP = True
SNIFF_TIMEOUT = 1800
RELEASE_TIMEOUT = 10

rtmp_streams = {}
mms_streams = {}
wmsp_streams = {}
rtsp_streams = {}
http_streams = {}

out_mode = 'txt'
quit_first = False
result = []

sniff_result_file = None


def reverse_session_id(session_id):
    """Get reverse session_id.

    i.e. (A.ip, A.port, B.ip, B.port) -> (B.ip, B.port, A.ip, A.port)"""
    return session_id[2:] + session_id[:2]


def packet_handler(pkt):
    """Packet Handler Callback from scapy."""
    logger = logging.getLogger(__name__)

    global rtmp_streams
    global mms_streams
    global wmsp_streams
    global rtsp_streams
    global http_streams
    global out_mode
    global quit_first
    global sessions
    global result

    found = False
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        # Collect only data with application layer payload

        # hexdump(pkt.load)
        # print

        # Follow TCP streams with tuple of (ip_src, port_src, ip_dst, port_dst)
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        port_src = str(pkt[TCP].sport)
        port_dst = str(pkt[TCP].dport)
        this_seq = pkt[TCP].seq
        next_seq = this_seq + len(pkt.load)
        session_id = (ip_src, port_src, ip_dst, port_dst)

        # Exclude TCP retransmission
        if session_id in sessions and this_seq < sessions[session_id]:
            logger.debug("TCP retransmission at seq %d", this_seq)
            return
        sessions[session_id] = next_seq

        '''Payloads of Several Packets are Concatenated into One Stream'''
        if SNIFF_RTMP:
            # Clear old cached sessions to release memory
            all_sessions = list(rtmp_streams.keys())
            for i in all_sessions:
                if time.time() - rtmp_streams[i].timestamp >= RELEASE_TIMEOUT:
                    del rtmp_streams[i]
                    logger.debug("Removed rtmp session %s", repr(i))

            if session_id not in rtmp_streams:
                rtmp_streams[session_id] = Stream(pkt.load)
            else:
                if rtmp_streams[session_id].dont_scan_again:
                    return
                rtmp_streams[session_id].append_data(pkt.load)
            rtmp_streams[session_id].timestamp = time.time()

            # Min size that an RTMP stream must have to contains useful data...
            if rtmp_streams[session_id].size > 0x600 * 2:
                logger.debug(
                    "Dissecting stream with RTMP parser: %s", session_id)

                rtmp = RTMPParser()
                try:
                    cmds = rtmp.rtmp_parse_stream(rtmp_streams[session_id])

                    # If have 2 AMF commands (play and connect), print the
                    # results
                    if cmds is not None and 'url' in cmds.stream_info:
                        logger.info("RTMP stream found")
                        result.append(('rtmp', cmds.output(out_mode)))
                        rtmp_streams[session_id].dont_scan_again = True
                        rtmp_streams[session_id].offset = 0
                        found = True
                    else:
                        logger.debug("RTMP stream not found, reset")
                        rtmp_streams[session_id].offset = 0

                except StreamNoMoreBytes:
                    logger.debug("No more bytes to read from the stream")
                    rtmp_streams[session_id].offset = 0
                    # traceback.print_exc()

                except Exception as e:
                    logger.error("RTMP Parser Error: %s", e)
                    rtmp_streams[session_id].offset = 0
                    traceback.print_exc()

        '''Several Packets are Parsed and Thrown Away'''
        if SNIFF_MMSP:
            # mms command cannot be chunked, so there is no need to concatenate
            # packet data
            all_sessions = list(mms_streams.keys())
            for i in all_sessions:
                if time.time() - mms_streams[i]['timestamp'] \
                        >= RELEASE_TIMEOUT:
                    del mms_streams[i]
                    logger.debug("Removed mms session %s", repr(i))

            if session_id not in mms_streams:
                mms_streams[session_id] = {'dont_scan_again': False,
                                           'cmds': MMSCommands(),
                                           'timestamp': time.time()}
            elif mms_streams[session_id]['dont_scan_again'] is True:
                return

            logger.debug("Dissecting stream with MMSP parser: %s", session_id)
            mms = MMSParser()
            packet = Stream(pkt.load)
            try:
                cmd = mms.mms_parse_packet(packet)
                if cmd:
                    mms_streams[session_id]['cmds'].add(cmd)
                    mms_streams[session_id]['timestamp'] = time.time()

                if mms_streams[session_id]['cmds'].count() == 2:
                    logger.info('MMSP stream found')
                    result.append(
                        ('mms',
                         mms_streams[session_id]['cmds'].output('txt')))
                    mms_streams[session_id]['dont_scan_again'] = True
                    found = True
            except StreamNoMoreBytes:
                logger.debug("Not mms command packet, continue")
            except:
                logger.error("MMS Parser Error: %s", traceback.format_exc())

        '''Several Packets are Parsed and Thrown Away'''
        if SNIFF_HTTP:
            all_sessions = list(http_streams.keys())
            for i in all_sessions:
                if time.time() - http_streams[i]['timestamp'] \
                        >= RELEASE_TIMEOUT:
                    del http_streams[i]
                    logger.debug("Removed http session %s", repr(i))

            if session_id not in http_streams:
                http_streams[session_id] = {'dont_scan_again': False,
                                            'cmds': HTTPCommands(),
                                            'timestamp': time.time()}
            elif http_streams[session_id]['dont_scan_again'] is True:
                return

            logger.debug("Dissecting stream with HTTP parser: %s", session_id)
            http = HTTPParser()
            packet = Stream(pkt.load)
            try:
                cmd = http.http_parse_packet(packet)
                if cmd:
                    if cmd.name == 'GET':
                        http_streams[session_id]['cmds'].add(cmd)
                        http_streams[session_id]['timestamp'] = time.time()
                    elif cmd.name == 'STREAM_RESP':
                        rsession_id = reverse_session_id(session_id)
                        if rsession_id not in http_streams:
                            logger.debug(
                                "Response indicates stream"
                                "while no request found")
                        else:
                            rcmd = http_streams[rsession_id]['cmds'].get('GET')
                            if not rcmd:
                                logger.debug(
                                    "Reverse session has no GET request")
                            else:
                                logger.info('HTTP stream found')
                                result.append(
                                    ('http',
                                     http_streams[rsession_id]['cmds'].
                                     output('txt')))
                                http_streams[
                                    rsession_id]['dont_scan_again'] = True
                                found = True
            except StreamNoMoreBytes:
                logger.debug("Not http command packet, continue")
            except Exception as e:
                logger.error("HTTP Parser Error: %s", traceback.format_exc())

        '''Only ONE Packet from Client to Server is Needed'''
        if SNIFF_WMSP:
            if session_id in wmsp_streams:
                return

            wmsp_streams[session_id] = Stream(pkt.load)
            wmsp_streams[session_id].timestamp = time.time()

            logger.debug("Dissecting stream with WMSP parser: %s", session_id)
            wmsp = WMSPParser()
            try:
                cmd = wmsp.wmsp_parse_packet(wmsp_streams[session_id],
                                             pkt[TCP].dport)
                if cmd:
                    cmds = WMSPCommands()
                    cmds.add(cmd)
                    logger.info('WMSP stream found')
                    result.append(('wmsp', cmds.output('txt')))
                    found = True
            except StreamNoMoreBytes:
                logger.debug("Not wmsp get packet, continue")
            except Exception as e:
                logger.error("WMSP Parser Error: %s", e)
                traceback.print_exc()
            finally:
                del wmsp_streams[session_id]
                logger.debug("Removed wmsp session %s", repr(session_id))

        '''Only ONE Packet from Client to Server is Needed'''
        if SNIFF_RTSP:
            if session_id in rtsp_streams:
                return

            rtsp_streams[session_id] = Stream(pkt.load)
            rtsp_streams[session_id].timestamp = time.time()

            logger.debug("Dissecting stream with RTSP parser: %s", session_id)
            rtsp = RTSPParser()
            try:
                cmd = rtsp.rtsp_parse_packet(rtsp_streams[session_id])
                if cmd:
                    cmds = RTSPCommands()
                    cmds.add(cmd)
                    logger.info('RTSP stream found')
                    result.append(('rtsp', cmds.output('txt')))
                    found = True
            except StreamNoMoreBytes:
                logger.debug("Not rtsp get packet, continue")
            except Exception as e:
                logger.error("RTSP Parser Error: %s", e)
                traceback.print_exc()
            finally:
                del rtsp_streams[session_id]
                logger.debug("Removed rtsp session %s", repr(session_id))

        if found:
            with open(sniff_result_file, 'wb') as fd:
                pickle.dump(result, fd)

    if quit_first and found:
        exit(0)


def setup_arg_parser():
    parser = argparse.ArgumentParser(description="")

    parser.add_argument(
        "-t", "--timeout", action="store", dest="timeout",
        default=SNIFF_TIMEOUT, help="Timeout diff from default")
    parser.add_argument("--tmp_dir", default='/tmp')
    parser.add_argument("--result_pickle", default='qtsniffer.pickle')
    parser.add_argument("--log_dir", default='/tmp')
    parser.add_argument("--log_file", default='qtsniffer.log')

    group_input = parser.add_argument_group("Input")
    group = group_input.add_mutually_exclusive_group()
    group.add_argument("-i", action="store", dest="device",
                       help="Device to sniff on"
                            "(Default: sniffs on all devices)")
    group.add_argument(
        "-f", action="store", dest="pcapfile", help="PCAP file to read from")

    group_output = parser.add_argument_group("Output format")
    group = group_output.add_mutually_exclusive_group()
    group.add_argument(
        "--out-list", action='store_const', const="list", dest="out_mode",
        help="Prints the RTMP data as list (Default)")
    group.add_argument(
        "--out-m3u", action='store_const', const="m3u", dest="out_mode",
        help="Prints the RTMP data as m3u entry")
    group.add_argument(
        "--out-rtmpdump", action='store_const', const="rtmpdump",
        dest="out_mode", help="Prints the RTMP data in the rtmpdump format")

    group_input = parser.add_argument_group("Additional options")
    # group_input.add_argument("-p", action="store", dest="port", default=0,
    # type=int, help="RTMP port (Default: sniffs on all ports)")
    group_input.add_argument("--one", action="store_true", dest="quit_first",
                             help="Quit after the first stream found")
    group_input.add_argument(
        "--debug", action="store_true", help="Enable DEBUG mode")

    args = parser.parse_args()
    return args


def sniff(pcapfile=None, device=None, timeout=SNIFF_TIMEOUT):
    # Read from dump file rather than sniffing
    logger = logging.getLogger(__name__)
    if pcapfile:
        logger.info("Read packets from dump file '%s'", pcapfile)
        try:
            _sniff(offline=pcapfile, store=0,
                   filter="tcp", prn=packet_handler, timeout=timeout)
        except Exception as e:
            logger.error(e)
            traceback.print_exc()

    # Sniffing on the specified device
    elif device:
        logger.info("Starting sniffing on %s", device)
        try:
            _sniff(iface=device, store=0, prn=packet_handler, timeout=timeout)
        except socket.error as e:
            logger.error("Error opening %s for sniffing: %s", (device, e))
            exit(1)


def main():
    args = setup_arg_parser()

    log_format = "[%(levelname)s]<%(module)s>-%(funcName)s:"
    log_format += " %(message)s --- %(asctime)s"
    log_formatter = logging.Formatter(log_format)

    logger = logging.getLogger()
    if os.path.isdir(args.log_dir):
        logfile = os.path.join(args.log_dir, args.log_file)
        logfile_handler = logging.FileHandler(logfile)
        logfile_handler.setFormatter(log_formatter)
        logger.addHandler(logfile_handler)
    else:
        print("Specified log_dir %s not exists, only write to stderr")

    logstream_handler = logging.StreamHandler()
    logstream_handler.setFormatter(log_formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(logstream_handler)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info('-' * 20 + " Stream Sniffer " + '-' * 20)

    # listen_port = args.port
    global out_mode, quit_first
    out_mode = args.out_mode
    quit_first = args.quit_first

    global sniff_result_file
    sniff_result_file = os.path.join(args.tmp_dir, args.result_pickle)

    if args.pcapfile:
        sniffed_device = None
    else:
        if args.device:
            sniffed_device = args.device
        else:
            for ifacename in netifaces.interfaces():
                addrs = netifaces.ifaddresses(ifacename)
                if netifaces.AF_INET in addrs:
                    if ifacename not in all_devices:
                        all_devices[ifacename] = []
                    for i in addrs[netifaces.AF_INET]:
                        all_devices[ifacename].append(i['addr'])
            logger.debug("Available devices: %s", all_devices)
            sniffable_devices = [i for i in all_devices
                                 if '127.0.0.1' not in all_devices[i]]
            sniffed_device = sniffable_devices[0]

    sniff(args.pcapfile, sniffed_device, int(args.timeout))


if __name__ == '__main__':
    main()
