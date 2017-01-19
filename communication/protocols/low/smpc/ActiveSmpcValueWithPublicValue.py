""" CoinParty - Active SMPC Value with public value
    An abstract class for SMPC values that require communication between peers
    and that yield a publicly known value (such as a common public key) as a
    result.

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
from ActiveSmpcValue import ActiveSmpcValue
from ..exceptions import AbstractClassError


class ActiveSmpcValueWithPublicValue(ActiveSmpcValue):
    """ Defines an active SMPC value that implicitly recombines a public value
        corresponding to the given secret share. E.g., key derivation
        algorithms or a usual Shamir recombiner belong in this category. """

    def __init__(self, id, index, state):
        super(ActiveSmpcValueWithPublicValue, self).__init__(id, index, state)
        self._public_value_deferred = Deferred()
        self._public_value = None
        self._public_value_dependents = []

    def __statelen__(self):
        return super(ActiveSmpcValueWithPublicValue, self).__statelen__() + 1

    def __getstate__(self):
        state = super(ActiveSmpcValueWithPublicValue, self).__getstate__()
        state += (self._public_value,)
        return state

    def __setstate__(self, state):
        super(ActiveSmpcValueWithPublicValue, self).__setstate__(state)
        it = iter(state)
        for i in xrange(0, super(ActiveSmpcValueWithPublicValue, self).__statelen__()):
            next(it)
        self._public_value = next(it)
        self._public_value_deferred = Deferred()
        self._public_value_deferred.callback(None)

    def informDependentPublicDeferreds(self):
        while len(self._public_value_dependents) > 0:
            d = self._public_value_dependents.pop()
            d.callback(self._public_value)
        return self._public_value

    def getPublicValue(self):  # Uses same idea for "cloning" a deferred as viff.util.clone_deferred; but later
        deferred = Deferred()
        if (self._public_value is None):
            self._public_value_dependents.append(deferred)
        else:
            deferred.callback(self._public_value)
        return deferred

    def computePublicValue(self, _):
        return AbstractClassError()
