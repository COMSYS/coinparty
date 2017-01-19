""" CoinParty - Initialization Protocol
    This protocol performs one-time initialization steps.
    This only involves calling JFDKG once to obtain the
    random EC point H used by EC-DKG subsequently.

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

def initialize(_, state):
    value = state.smpc.newValue('jfdkg', state, 'H')
    value.initialize()
    deferred = value.getPublicValue()
    return deferred
