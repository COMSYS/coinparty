""" CoinParty - Shuffling State
    Contains state variables that are relevant to the shuffling phase.

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


class ShufflingState():

    def __init__(self, number_mixpeers):
        self._checksums = [None] * number_mixpeers
        self._addr_deferreds = [Deferred() for i in xrange(number_mixpeers)]
        self._shuffling_deferred = Deferred()
        self._initialize_deferred = Deferred()

    """ The checksum as constructed from hashshares. """

    def initialized(self):
        self._initialize_deferred.callback(None)

    def storeChecksums(self, checksums):
        self._checksums = checksums
        return

    def storeChecksum(self, checksum, index):
        self._checksums[index] = checksum
        return checksum

    def getChecksum(self, index=-1):
        return self._checksums[index]

    def receivedAddrBroadcast(self, addresses, rank):
        def _fire_addr_deferred(_, rank):
            d = self._addr_deferreds[rank]
            if (not d.called):
                d.callback((addresses, rank))
            return d
        self._initialize_deferred.addCallback(_fire_addr_deferred, rank=rank)
        return self._initialize_deferred

    def addAddrDeferredCallback(self, cb):
        for d in self._addr_deferreds:
            d.addCallback(cb)
        return

    def getShufflingDeferred(self):
        return self._shuffling_deferred

    def fireShufflingDeferred(self):
        self._shuffling_deferred.callback(None)
