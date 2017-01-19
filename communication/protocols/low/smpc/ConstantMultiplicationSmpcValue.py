""" CoinParty - Constant Multiplication SMPC Value
    A class defining the multiplication of a secret share with a constant;
    no communication required.

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

from twisted.internet.defer import maybeDeferred

from SmpcValue import SmpcValue
from ..constants import bitcoin_order as standard_order


class ConstantMultiplicationSmpcValue(SmpcValue):
    """ Given a constant and a share of a shared value, compute the secret
        share as the product of both values. """

    def __init__(self, state):
        super(ConstantMultiplicationSmpcValue, self).__init__(state)

    def __statelen__(self):
        return super(ConstantMultiplicationSmpcValue, self).__statelen__()

    def __getstate__(self):
        return super(ConstantMultiplicationSmpcValue, self).__getstate__()

    def __setstate__(self, state):
        super(ConstantMultiplicationSmpcValue, self).__setstate__(state)

    def initialize(self, constant_factor, smpc_value, order=standard_order):
        def _fire_secret_share(factor2):
            self._secret_share = (constant_factor * factor2) % order
            self._secret_share_deferred.callback(self._secret_share)

        factor2 = maybeDeferred(smpc_value.getSecretShare)
        factor2.addCallback(_fire_secret_share)
        return self._secret_share_deferred
