import sys


def str2num(s):
    """Convert a number to a chr."""

    l = 0
    try:
        for i in range(len(s)):
            l = l << 8
            if sys.version_info.major == 3:
                l += s[i]
            else:
                l += ord(s[i])
        return l
    except:
        return 0


def bytechr(i):
    if isinstance(i, bytes):
        return i
    if sys.version_info.major == 3:
        return bytes([i])
    else:
        return chr(i)
