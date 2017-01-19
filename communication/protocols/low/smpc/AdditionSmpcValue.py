""" CoinParty - Addition SMPC Value
    A class defining an ADD gate for secret shares; no communication required.

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

from twisted.internet.defer import DeferredList, maybeDeferred

from SmpcValue import SmpcValue
from ..constants import bitcoin_order as standard_order


class AdditionSmpcValue(SmpcValue):
    """ Given shares of two shared values, compute the secret share as the sum
        of both values. """

    def __init__(self, state):
        super(AdditionSmpcValue, self).__init__(state)

    def __statelen__(self):
        return super(AdditionSmpcValue, self).__statelen__()

    def __getstate__(self):
        return super(AdditionSmpcValue, self).__getstate__()

    def __setstate__(self, state):
        return super(AdditionSmpcValue, self).__setstate__(state)

    def initialize(self, smpc_value1, smpc_value2, order=standard_order):
        def _fire_secret_share(summands):
            self._secret_share = (summands[0][1] + summands[1][1]) % order
            self._secret_share_deferred.callback(self._secret_share)
            return
        summand1 = maybeDeferred(smpc_value1.getSecretShare)
        summand2 = maybeDeferred(smpc_value2.getSecretShare)
        d = DeferredList([summand1, summand2])
        d.addCallback(_fire_secret_share)
        return self._secret_share_deferred
