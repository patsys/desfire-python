"""Misc. utility functions."""


import sys
import crcmod.predefined

if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *
import json
from binascii import unhexlify

from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long


def byte_array_to_human_readable_hex(bytes):
    return "".join("%02X " % b for b in bytes)

def getInt(data,byteorder='big'):
    if isinstance(data,int):
        return data
    if isinstance(data,str):
        data=bytearray.fromhex(data)
    if isinstance(data,bytearray):
        data=bytes(data)
    return int.from_bytes(data, byteorder=byteorder)

def getList(data,byteSize=2,byteorder='big'):
    if isinstance(data, str):
        return list(bytearray.fromhex(data))
    elif isinstance(data, bytearray):
        return list(data)
    elif isinstance(data, int):
        return list(data.to_bytes(byteSize, byteorder=byteorder))
    elif isinstance(data,bytes):
        return list(data)
    return data
     

def getBytes(data,byteSize=2):
    if isinstance(data, str):
        return bytes(bytearray.fromhex(data))
    elif isinstance(data, bytearray):
        return bytes(data)
    elif isinstance(data, int):
        return data.to_bytes(byteSize, byteorder='big')
    return data


def CRC32(data):
    crc=[0xff,0xff,0xff,0xff]
    crc32_func = crcmod.predefined.mkCrcFun('jamcrc')
    return crc32_func(bytes(data))

def shift_bytes(bs, xor_lsb=0):
    num = (bytes_to_long(bs)<<1) ^ xor_lsb
    return long_to_bytes(num, len(bs))[-len(bs):]
