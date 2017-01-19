""" CoinParty - Wrapper SMCP Value
    Wrapper class to be used if usual Python variables serve as input for SMPC
    values, e.g., secret shares, so they can be combined with other SMPC
    values afterwards.

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

from SmpcValue import SmpcValue


class WrapperSmpcValue(SmpcValue):
    """ Defines a simple wrapper for secret shares to be used with other
        SMPC value objects. """

    def __init__(self, state):
        super(WrapperSmpcValue, self).__init__(state)

    def __statelen__(self):
        return super(WrapperSmpcValue, self).__statelen__()

    def __getstate__(self):
        return super(WrapperSmpcValue, self).__getstate__()

    def __setstate__(self, state):
        super(WrapperSmpcValue, self).__setstate__(state)

    def initialize(self, secret_share):
        self._secret_share = secret_share
        self._secret_share_deferred.callback(secret_share)
        return self._secret_share_deferred
