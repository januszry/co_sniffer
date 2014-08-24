#!/usr/bin/env python2.7

def str2num(s):
    ''' Convert a number to a chr '''

    i = 0
    l = 0
    try:
        for i in range(len(s)):
            l = l << 8
            l += ord(s[i])
        return l
    except:
        return 0
