""" CoinParty - SMCP Value
    An interface for CoinParty SMPC protocols.

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

from twisted.internet.defer import Deferred

from ..constants import bitcoin_order as standard_order
from ..exceptions import AbstractClassError


class SmpcValue(object):
    """ Defines most basic functionality of each object that represents
        an SMPC value. """

    def __init__(self, state):
        self._n = state.mixnet.getMixnetSize()
        self._t = state.mixnet.getMixpeerThreshold()
        self._secret_share_deferred = Deferred()
        self._order = standard_order
        self._secret_share = None
        self._secret_share_dependents = []

    def __statelen__(self):
        return 4

    def __getstate__(self):
        state = ()
        state += (self._n,)
        state += (self._t,)
        state += (self._order,)
        state += (self._secret_share,)
        return state

    def __setstate__(self, state):
        it = iter(state)
        self._n = next(it)
        self._t = next(it)
        self._order = next(it)
        self._secret_share = next(it)
        self._secret_share_deferred = Deferred()
        self._secret_share_deferred.callback(None)

    def getNumberShares(self):
        return self._n

    def getThreshold(self):
        return self._t

    def getSecretShare(self):  # Uses same idea for "cloning" a deferred as viff.util.clone_deferred
        deferred = Deferred()
        if (self._secret_share is None):
            self._secret_share_dependents.append(deferred)
        else:
            deferred.callback(self._secret_share)
        return deferred

    def informDependentSecretDeferreds(self):
        while len(self._secret_share_dependents) > 0:
            d = self._secret_share_dependents.pop()
            d.callback(self._secret_share)
        return self._secret_share

    def initialize(self):
        """ Reminder that each SMPC value must define an initialize() function.
            However, the signature may vary. This function is intended to
            mimick a callback of twisted's Deferreds. In fact, most likely this
            WILL trigger a Deferred. """
        return AbstractClassError()
