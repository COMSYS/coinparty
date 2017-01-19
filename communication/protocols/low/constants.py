""" CoinParty - Crypto Constants
    Cryptographic parameters used by CoinParty.

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

from ecdsa.ellipticcurve import CurveFp, Point

bitcoin_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L

""" When secret-sharing hashs (arbitrary 256-bit values), bitcoin_order may
    not be used, since it is too small to fit each possible hash value.
    Thus, we use the prime (2^265)-49, which is sufficiently large.
    Prime derived from http://primes.utm.edu/lists/2small/200bit.html """
hash_order =   0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcf
hash_modulus = 0x10000000000000000000000000000000000000000000000000000000000000000

""" Bitcoin ECC parameters
    _p, _a, _b:  Description of secp256k1 for the ecdsa module
    _Gx, Gy:     Coordinates of generator (uncompressed form)
    n:           Order of the generator
    _h:          Cofactor

    c.f.: https://en.bitcoin.it/wiki/Secp256k1 """
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000L
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_h  = 0x01L

bitcoin_curve = CurveFp(_p, _a, _b)
G = Point(bitcoin_curve, _Gx, _Gy, n)
