""" CoinParty - Basic SMPC Functionality
    Absolute building blocks needed for secret sharing.

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

from Crypto.Random import random
from ..constants import bitcoin_order as standard_order


def randint(order=standard_order):
    """ Return a random integer from the range [0, order). """
    return random.randint(0, order - 1)


def invert(a, order=standard_order):
    """ Invert a modulo order. Therefore, order must be prime. """
    def extended_gcd(a, b):
        """The extended Euclidean algorithm. (Taken from VIFF.) """
        x = 0
        lastx = 1
        y = 1
        lasty = 0
        while b != 0:
            quotient = a // b
            a, b = b, a % b
            x, lastx = lastx - (quotient * x), x
            y, lasty = lasty - (quotient * y), y
        return (lastx, lasty, a)

    if (a == 0):
        raise ZeroDivisionError('cannot_invert_zero')
    return extended_gcd(a % order, order)[0]
