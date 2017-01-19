""" CoinParty - Commitment State
    Contains state variables that are relevant to the commitment phase.

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

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.task import deferLater, LoopingCall

from time import time
from hashlib import sha256
import hmac

from ..low.log import Logger
log = Logger('commit_state')


class CommitmentState():

    def __init__(self, min_peers=3, max_peers=3, timeout_mins=1):
        self._min_peers = min_peers
        self._max_peers = max_peers
        self._number_peers = 0
        self._timeout_mins = timeout_mins
        self._allow_min_peers = False
        self._start_time = None
        self._pending_nonces = []

        self._threshold_reached = Deferred()
        self._polling_loopcall = None  # This is set using setPollingDeferred
        self._polling_loopcall_deferred = None  # Set together with the loopcall itself
        self._timeout_deferred = None  # Set by startPeerGathering

    def increasePeerCount(self):
        self._number_peers += 1

    def timeoutReached(self):
        log.warning('Timeout reached! Allowing minimal number of participants.')
        self._allow_min_peers = True
        if (self._number_peers >= self._min_peers):
            self._threshold_deferred.callback(None)
        return

    def startPeerGathering(self):
        log.debug('Starting timeout for input peer gathering.')
        self._timeout_deferred = deferLater(reactor, self._timeout_mins * 60, self.timeoutReached)
        self._start_time = time()
        return

    def getRemainingTime(self):
        remaining_time = int((self._start_time + (60 * self._timeout_mins)) - time())
        return remaining_time if (remaining_time > 0) else 0

    def minInputPeerThresholdReached(self):
        return True if (self._number_peers >= self._min_peers) else False

    def getMinimumNumberInputPeers(self):
        return self._min_peers

    def checkInputPeerThreshold(self, v=None):
        log.debug('Checking threshold...')
        if ((self._allow_min_peers and self._number_peers >= self._min_peers) or self._number_peers == self._max_peers):
            if (not self._allow_min_peers):
                self._timeout_deferred.cancel()
                log.debug('Cancelling timeout deferred!')
            self._threshold_reached.callback(None)
            log.debug('Firing threshold deferred!')
        return v

    def addPendingNonce(self, nonce):
        self._pending_nonces.append(nonce)
        return

    def checkPendingNonce(self, secret, unhashed_nonce):
        h = hmac.new(secret, unhashed_nonce, sha256).hexdigest()
        try:
            index = self._pending_nonces.index(h)
        except:
            return False
        del self._pending_nonces[index]
        return True

    """ Threshold deferred denoting sufficient number of input peers """

    def getThresholdDeferred(self):
        return self._threshold_reached

    """ Polling loopcall (c.f. cronjob) """

    def setPollingDeferred(self, f, period, *a, **kw):
        """ I take the function to be called periodically and
            a frequency to call it, and optionally additional
            parameters for that function. """
        self._polling_loopcall = LoopingCall(f, *a, **kw)
        d = self._polling_loopcall.start(period)
        self._polling_loopcall_deferred = d
        return d # For adding callbacks

    def getPollingDeferred(self):
        return self._polling_loopcall_deferred

    def firePollingDeferred(self):
        self._polling_loopcall.stop()
