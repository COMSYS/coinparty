""" CoinParty - Shamir Secret Sharing
    Practically a re-implementation of VIFF's approach to Shamir sharing.
    Additionally, an implementation of the Berlekamp-Welch algorithm.

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

# Copyright 2008 VIFF Development Team.
#
# This file is part of VIFF, the Virtual Ideal Functionality Framework.
#
# VIFF is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License (LGPL) as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# VIFF is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
# Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with VIFF. If not, see <http://www.gnu.org/licenses/>.

from ..constants import bitcoin_order as standard_order
import base as smpcbase

""" Caching of "participating player signatures", meaning: Keep track of the
    recombination vectors used for different sets of considered shares.
    Idea taken from VIFF. Addition to VIFF: the used order is part of the
    caching key as well. In VIFF, viff.field.GF handles this implicitly. """
_recombination_vectors = {}


def _construct_equation_system(shares, t, order=standard_order):
    n = len(shares)
    matrix = [[FieldElement((i + 1)**j, order) for j in xrange(0, n - t)] + [FieldElement(-shares[i][1] * ((i + 1)**j), order) for j in xrange(0, t)] for i in xrange(0, n)]
    solution = [FieldElement(shares[i][1] * ((i + 1)**t), order) for i in xrange(0, n)]
    return (matrix, solution)


def _solve_equation_system(matrix, solution, order=standard_order):
    n = len(matrix)
    Ab = [[matrix[i][j] for j in xrange(0, n)] + [solution[i]] for i in xrange(0, n)]

    for i in xrange(0, n):
        p = FieldElement(0, order)
        p_ind = -1
        for k in xrange(i, n):
            if (Ab[k][i] > p):
                p = Ab[k][i]
                p_ind = k
        if (p_ind == -1):
            return None
        Ab[i], Ab[p_ind] = Ab[p_ind], Ab[i]
        Ab[i] = [Ab[i][j] / p for j in xrange(0, n + 1)]
        for k in xrange(i + 1, n):
            Ab[k] = [Ab[k][j] - (Ab[k][i] * Ab[i][j]) for j in xrange(0, n + 1)]

    for i in reversed(xrange(0, n)):
        for k in xrange(0, i):
            Ab[k] = [Ab[k][j] - (Ab[k][i] * Ab[i][j]) for j in xrange(0, n + 1)]

    x = [Ab[i][-1] for i in xrange(0, n)]
    return x


class FieldElement(object):
    """ Helper class, which is probably very similar to VIFF's class """
    def __init__(self, v, order=standard_order):
        self.order = order
        self.v = int(v) % self.order

    def __eq__(self, x):
        if (isinstance(x, FieldElement)):
            return (self.v == x.v and self.order == x.order)
        elif isinstance(x, int):
            return (self.v == x % self.order)
        else:
            return NotImplemented

    def __ne__(self, x):
        return not self.__eq__(x)

    def __add__(self, x):
        v2 = x.v if isinstance(x, FieldElement) else x
        return FieldElement(self.v + v2, self.order)
    __radd__ = __add__

    def __sub__(self, x):
        v2 = x.v if isinstance(x, FieldElement) else x
        return FieldElement(self.v - v2, self.order)

    def __rsub__(self, x):
        v2 = x.v if isinstance(x, FieldElement) else x
        return FieldElement(v2 - self.v, self.order)

    def __mul__(self, x):
        v2 = x.v if isinstance(x, FieldElement) else x
        return FieldElement(self.v * v2, self.order)
    __rmul__ = __mul__

    def __div__(self, x):
        v2 = x.v if isinstance(x, FieldElement) else x
        return FieldElement(self.v * smpcbase.invert(v2, self.order), self.order)

    def __rdiv__(self, x):
        v2 = x.v if isinstance(x, FieldElement) else x
        return FieldElement(smpcbase.invert(self.v, self.order) * v2, self.order)

    def __lt__(self, x):
        v2 = x if isinstance(x, FieldElement) else FieldElement(x, self.order)
        return (self.v < v2.v)

    def __le__(self, x):
        return (self < x or self == x)

    def __gt__(self, x):
        v2 = x if isinstance(x, FieldElement) else FieldElement(x, self.order)
        return (self.v > v2.v)

    def __ge__(self, x):
        return (self > x or self == x)

    def __repr__(self):
        return 'FE(' + str(self.v) + ')'

    def __str__(self):
        return 'FE(' + str(self.v) + ')'

    def __int__(self):
        return self.v


def share(s, n, t, order=standard_order, return_factors=False):
    """ Split the secret s into n-many shares, of which any set of t+1 shares
        is sufficient to reconstruct s.

        s                 Secret to be secret-shared.
        n                 Total number of players (total number of shares
                          created).
        t                 Threshold of the sharing. (t+1) correct shares
                          needed for recombination.
        order             Shamir polynomials are created over the Galois
                          field of order "order". "order" must be prime,
                          and s < order must hold.
        return_factors    If true, the return value will be (shares, factors),
                          otherwise only shares are returned. """

    def _horner(factors, x):
        """ Horner scheme. Factors must be in this order:
            f(x) = a_0 + x * a_1 + x^2 * a_2 + ... + x^n * a_n """
        result = 0
        for f in factors:
            result = (x * result + f) % order
        return result

    # factors in reversed order for horner scheme
    factors = [smpcbase.randint(order)] * t + [s]
    shares = [(x + 1, _horner(factors, x + 1)) for x in xrange(0, n)]
    if (return_factors):
        return (shares, factors[::-1])  # reversed(factors) does not yield a list, but an iterator
    else:
        return shares


def _berlekamp_welch(shares, t, secret_order=standard_order):

    def _split_factors(coeffs, t):
        n = len(coeffs)
        Q = [c for c in coeffs[:(n - t)]]
        E = [c for c in coeffs[-t:]] if t > 0 else []
        E += [FieldElement(1, secret_order)]
        return (Q, E)

    def _get_P(Q, E):
        """ Division of two polynomials. """
        Pt = []
        Qt = [Q[i] for i in reversed(xrange(0, len(Q)))]
        Et = [E[i] for i in reversed(xrange(0, len(E)))]
        # Remove leading 0s of Qt (except Qt = 0)
        while (len(Qt) > 1 and Qt[0] == FieldElement(0, secret_order)):
            Qt = Qt[1:]
        while (len(Qt) >= len(Et)):
            c = Qt[0] / Et[0]
            for i in xrange(0, len(E)):
                Qt[i] -= c * Et[i]
            if (Qt[0] == 0):
                Qt = Qt[1:]
                Pt.append(c)
            else:
                raise ValueError('Error in polynomial division.')
        remainder = [x for x in reversed(Qt)]
        while (len(remainder) > 0 and remainder[0] == FieldElement(0, secret_order)):
            remainder = remainder[1:]
        while (len(Pt) > t + 1 and Pt[0] == 0):  # Remove leading 0s from result
            Pt = Pt[1:]
        P = [x for x in reversed(Pt)]
        return (P, remainder)

    x = None
    th = t + 1
    while (x is None):
        th -= 1
        if (th < 0):
            raise ValueError('unexpected_matrix_singularity')
        (matrix, b) = _construct_equation_system(shares, th, secret_order)
        x = _solve_equation_system(matrix, b, secret_order)

    (Q, E) = _split_factors(x, th)
    (P, remainder) = _get_P(Q, E)
    if (len(remainder) > 0):
        return None
    secret = int(P[0]) % secret_order
    return secret


def recombine(unf_shares, t, x=0, order=standard_order, robust=True):
    """ Recombine shamir sharings.
        It is assumed that only valid shares are passed to this function.
        This can be achieved via Pedersen VSS, for instance.

        unf_shares The shares to be used for recombination
        t          Threshold for recombination. First (t+1) shares are used.
        x          [opt] Point that should be interpolated. Default: 0
                       (Recombine the secret value).
        order      [opt] Order of the finite field of the polynomial to be
                       interpolated. Default: order of secp256k1. """

    if (robust):
        replaced_shares = [(s[0], (s[1] if s[1] is not None else 0)) for s in unf_shares]
        replaced_shares.sort(key=lambda x: x[0])
        return _berlekamp_welch(replaced_shares, t, order)

    def _filter_shares(shares):
            return [s for s in shares if s[1] is not None][:t + 1]

    filtered_shares = _filter_shares(unf_shares)
    if (len(filtered_shares) != t + 1):
        return None

    players, shares = zip(*filtered_shares)
    cache_key = (order,) + players + (x, )

    try:
        lagranges = _recombination_vectors[cache_key]
        secret = sum(map(lambda x, y: (x * y) % order, shares, lagranges)) % order
    except KeyError:
        pass
    finally:
        lagranges = []
        for i in players:
            lagrange_factors = [
                ((k - x) * smpcbase.invert(k - i, order)) % order
                for k
                in players if k != i
            ]
            lagranges.append(reduce(lambda x, y: (x * y) % order, lagrange_factors))
        _recombination_vectors[cache_key] = lagranges
        secret = sum(map(lambda x, y: (x * y) % order, shares, lagranges)) % order
    return secret
