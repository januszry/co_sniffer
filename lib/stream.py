#!/usr/bin/env python2.7

from scapy.utils import hexdump


class Stream(object):

    def __init__(self, stream=""):
        self.stream = stream
        self.offset = 0
        self.size = len(stream)
        self.dont_scan_again = False
        self.timestamp = None

    def append_data(self, data):
        """Appends new data to the stream."""
        self.stream += data
        self.size += len(data)

    def dump(self):
        """Prints the stream."""
        hexdump(self.stream[self.offset:])

    def get_bytes(self, n):
        """Gets n bytes from the buffer and increments the offset."""

        if self.offset + n > self.size:
            raise StreamNoMoreBytes

        result = self.stream[self.offset:self.offset + n]
        self.offset = self.offset + n
        return result

    def get_byte(self):
        """Get a single byte as int from the stream."""
        return ord(self.get_bytes(1))

    def read_bytes(self, n):
        """Reads n bytes from the buffer without increments the offset."""
        if self.offset >= self.size:
            return None

        result = self.stream[self.offset:self.offset + n]
        return result

    def have_bytes(self):
        """Returns True if there are bytes to be read, False otherwise."""
        if self.offset >= self.size:
            return False
        else:
            return True


class StreamNoMoreBytes(Exception):
    pass
