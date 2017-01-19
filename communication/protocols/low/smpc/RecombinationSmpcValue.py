""" CoinParty - Recombination SMPC Value
    An implementation of secret share recombination

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

from math import ceil, log

from twisted.internet.task import deferLater
from .. import Requests as req
from ..constants import bitcoin_order as standard_order
from shamir import recombine
from ActiveSmpcValueWithPublicValue import ActiveSmpcValueWithPublicValue
from ..Transaction import BroadcastTransaction


class RecombinationSmpcValue(ActiveSmpcValueWithPublicValue):
    """ Decoupled recombining mechanism for secret shares. """

    def __init__(self, id, index, state):
        super(RecombinationSmpcValue, self).__init__(id, index, state)
        self._received_shares = [None] * self._n
        self._value_timeout = None

    def __statelen__(self):
        return super(RecombinationSmpcValue, self).__statelen__() + 1

    def __getstate__(self):
        state = super(RecombinationSmpcValue, self).__getstate__()
        state += (self._received_shares,)
        return state

    def __setstate__(self, state):
        super(RecombinationSmpcValue, self).__setstate__(state)
        it = iter(state)
        for i in xrange(0, super(RecombinationSmpcValue, self).__statelen__()):
            next(it)
        self._received_shares = next(it)

    @staticmethod
    def getAlgorithm():
        return 'rec'

    def initialize(self, smpc_value, order=standard_order):
        def _wait_for_values(_):
            return self._public_value_deferred

        def _inform_dependent_secret_deferreds(value):
            self.informDependentSecretDeferreds()
            return value

        def _inform_dependent_public_deferreds(value):
            self.informDependentPublicDeferreds()
            return value

        self._order = order
        self._secret_share_deferred = smpc_value.getSecretShare()
        self._secret_share_deferred.addCallback(_inform_dependent_secret_deferreds)
        self._secret_share_deferred.addCallback(self.distributeShares)
        self._secret_share_deferred.addCallback(_wait_for_values)
        self._public_value_deferred.addCallback(self.computePublicValue)
        self._public_value_deferred.addCallback(_inform_dependent_public_deferreds)
        return self._secret_share_deferred

    def startCollectingTimeout(self, v):
        self._value_timeout = deferLater(self._clock, self._timeout_duration, self.stopCollecting, None)
        self._value_timeout.addErrback(lambda x: None)
        return v

    def stopCollecting(self, _):
        if (self._value_timeout is not None and not self._value_timeout.called):
            self._value_timeout.cancel()
        if (not self._public_value_deferred.called):
            self._public_value_deferred.callback(None)

    def distributeShares(self, secret_share):
        self._secret_share = secret_share
        return self.sendPublicValues()

    def sendPublicValues(self):
        connected_peers = self._getConnectedPeers()
        seq = self._transactions.getNextSequenceNumber()
        length = int(ceil(log(self._order) / (8.0 * log(2))))
        binary_share = '{0:0{1}x}'.format(self._secret_share, 2 * length).decode('hex')
        msg = req.mpcp.encode(
            self._rank,
            seq,
            self._crypters[self._rank],
            self.getAlgorithm(),
            self.getID(),
            self.getIndex(),
            binary_share
        )
        share_deferred = self._transactions.addTransaction(
            BroadcastTransaction(
                self._rank,
                connected_peers,
                msg,
                seq,
                None
            )
        )
        self.receivedPublicValue(self._rank, binary_share)
        return share_deferred

    def receivedPublicValue(self, peer_rank, binary_value):
        if (self._public_value_deferred.called or self._received_shares[peer_rank] is not None):  # Ignore late/unexpected shares
            return
        value = int(binary_value.encode('hex'), 16)
        self._received_shares[peer_rank] = value
        if (len(filter(lambda c: c is None, self._received_shares)) == 0):
            self._public_value_deferred.callback(None)
        return

    def computePublicValue(self, _):
        shares = [(i + 1, self._received_shares[i]) for i in xrange(0, self._n)]
        self._public_value = recombine(shares, self._t, order=self._order)
        return self._public_value

    """ Decoupled recombination has no private information.
        Its purpose is to reveal private information and make it public. """

    def sendSecretShares(self):
        pass

    def receivedSecretShare(self, peer_rank, share):
        pass

    """ Decoupled recombination cannot utilize complaints.
        This is due to local computations that may have taken place to
        obtain the shares. """

    def sendComplaints(self, complain_error):
        pass

    def receivedComplaint(self, peer_rank, blamed_rank, opt=None):
        pass

    def sendComplaintReaction(self, blaming_peer):
        pass

    def receivedComplaintReaction(self, peer_rank, blaming_peer, reaction):
        pass

    def sendComplaintNaks(self, _):
        pass

    def receivedComplaintNak(self, peer_rank):
        pass

    def stopComplaintCollecting(self):
        pass
