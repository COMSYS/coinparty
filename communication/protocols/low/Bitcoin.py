""" CoinParty - Bitcoin Basics
    Serve very common Bitcoin constants and wrapped low-level functionality
    (such as address derivation) for convenience reasons.

    Copyright (C) 2016 Roman Matzutt, Henrik Ziegeldorf

    This file is part of CoinParty.

    CoinParty is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CoinParty is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with CoinParty.  If not, see <http://www.gnu.org/licenses/>. """

import bitcoin.base58 as base58
from ecdsa.ellipticcurve import Point

import hashlib
from binascii import hexlify, unhexlify
from struct import Struct as struct

from constants import bitcoin_curve as curve

from log import Logger
log = Logger('bitcoin')


""" Helper functions """


def get_version_byte(using_testnet):
    return chr(0x6F) if using_testnet else chr(0x00)


def serializeEcPoint(point, binary=True):
    ec_point_string = '04' + '{0:0{1}X}'.format(point.x(), 64) + '{0:0{1}X}'.format(point.y(), 64)
    if (binary):
        ec_point_string = unhexlify(ec_point_string)
    return ec_point_string


def deserializeEcPoint(point_str, binary=True):
    if (binary):
        point_hex = hexlify(point_str)
    else:
        point_hex = point_str
    if (point_hex[:2] != '04' or len(point_hex) != 130):
        return None
    x = int(point_hex[2:66], 16)
    y = int(point_hex[66:130], 16)
    return Point(curve, x, y)


def serializeEcPoints(points):
    serialized = struct('>B').pack(len(points))
    for i in xrange(len(points)):
        serialized += struct('>65s').pack(serializeEcPoint(points[i], binary=True))
    return serialized


def deserializeEcPoints(points_str):
    deserialized = []
    length = int(struct('>B').unpack(points_str[0])[0])
    for i in xrange(length):
        deserialized.append(deserializeEcPoint(points_str[((i * 65) + 1):(((i + 1) * 65) + 1)], binary=True))
    return deserialized


def ripemd_bc_checksum(ripe_hash):
    return hashlib.sha256(hashlib.sha256(ripe_hash).digest()).digest()[:4]


def computeBitcoinAddress(pubkey, using_testnet):
    hash256 = hashlib.sha256(pubkey).digest()
    hasher160 = hashlib.new('ripemd160')
    hasher160.update(hash256)
    hash160 = hasher160.digest()
    addr_raw = get_version_byte(using_testnet) + hash160
    addr_raw_checksum = addr_raw + ripemd_bc_checksum(addr_raw)
    addr = base58.encode(addr_raw_checksum).encode('utf8')
    return addr