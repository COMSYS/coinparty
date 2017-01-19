""" CoinParty - Share Multiplication SMPC Value
    An implementation of secret share multiplication.
    FIXME: This implementation is not yet secure against a 1/3-adversary!

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

from twisted.internet.defer import Deferred, DeferredList, maybeDeferred
from twisted.internet.task import deferLater
from twisted.internet import reactor

from ActiveSmpcValue import ActiveSmpcValue
from .. import Requests as req
import shamir
from ..constants import bitcoin_order as standard_order
from ..Transaction import EachcastTransaction
from ..log import Logger
log = Logger('mul')


class MultiplicationSmpcValue(ActiveSmpcValue):
    def __init__(self, id, index, state):
        super(MultiplicationSmpcValue, self).__init__(id, index, state)
        self._H_deferred = None
        try:
            def _set_H(H):
                self._H = H
            self._H_deferred = state.smpc.getValue('H').getPublicValue()
            self._H_deferred.addCallback(_set_H)
        except BaseException:
            self._H = None
        self._transmitted_secrets = [None] * self._n
        self._received_secrets = [None] * self._n
        self._shares_ready = Deferred()

    def __statelen__(self):
        return super(MultiplicationSmpcValue, self).__statelen__() + 3

    def __getstate__(self):
        state = super(MultiplicationSmpcValue, self).__getstate__()
        state += (self._H,)
        state += (self._transmitted_secrets,)
        state += (self._received_secrets,)
        return state

    def __setstate__(self, state):
        super(MultiplicationSmpcValue, self).__setstate__(state)
        it = iter(state)
        for i in xrange(0, super(MultiplicationSmpcValue, self).__statelen__()):
            next(it)
        self._H = next(it)
        self._transmitted_secrets = next(it)
        self._received_secrets = next(it)
        self._shares_ready = Deferred()
        self._shares_ready.callback(None)
        return

    @staticmethod
    def getAlgorithm():
        return 'mul'

    def initialize(self, smpc_value1, smpc_value2, order=standard_order, H=None):

        self._order = order

        def _fire_secret_share(factors):
            self._secret_share_deferred.callback((factors[0][1] * factors[1][1]) % self._order)
            return

        def _wait_for_values(_):
            return self._shares_ready

        def _inform_dependent_deferreds(value):
            self.informDependentSecretDeferreds()
            return value

        if (H is not None):  # Override local H if explicitly wished
            self._H = H

        if (smpc_value1.getThreshold() != smpc_value2.getThreshold()):
            raise RuntimeError('cant_multiply')
        self._subshare_t = 2 * smpc_value1.getThreshold()

        factor1 = maybeDeferred(smpc_value1.getSecretShare)
        factor2 = maybeDeferred(smpc_value2.getSecretShare)
        if (H is None and self._H_deferred is not None):
            d = DeferredList([factor1, factor2, self._H_deferred])
        else:
            d = DeferredList([factor1, factor2])
        d.addCallback(_fire_secret_share)
        self._secret_share_deferred.addCallback(self.createSubshares)
        self._secret_share_deferred.addCallback(self.startCollectingTimeout)
        self._secret_share_deferred.addCallback(self.distributeShares)
        self._secret_share_deferred.addCallback(_wait_for_values)
        self._secret_share_deferred.addCallback(self.recombineSecretShare)
        self._secret_share_deferred.addCallback(_inform_dependent_deferreds)
        return self._secret_share_deferred

    def startCollectingTimeout(self, _):
        deferLater(reactor, self._timeout_duration, self.stopCollecting, None)

    def stopCollecting(self, _):
        if (not self._shares_ready.called):
            self._shares_ready.callback(None)

    def createSubshares(self, multiplied_share):
        (subshares, factors) = shamir.share(multiplied_share, self._n, self._t, self._order, True)
        self._transmitted_secrets = [subshares[i][1] for i in xrange(0, self._n)]
        return

    def distributeShares(self, _):
        secrets_deferred = self.sendSecretShares()
        return secrets_deferred

    def sendSecretShares(self):
        """ Use point-to-point connection to send secrets. """
        connected_peers = self._getConnectedPeers()
        seq = self._transactions.getNextSequenceNumber()
        msgs = []
        binary_shares = []
        for r in self.getRankList(connected_peers):
            binary_shares.append('{0:0{1}x}'.format(self._transmitted_secrets[r], 64).decode('hex'))
        for peer in connected_peers:
            msg = req.mpcs.encode(
                self._rank,
                seq,
                self._crypters[self._rank],
                self.getAlgorithm(),
                self.getID(),
                self.getIndex(),
                binary_shares[peer['rank']]
            )
            msgs.append(msg)
        secrets_deferred = self._transactions.addTransaction(
            EachcastTransaction(
                self._rank,
                connected_peers,
                msgs,
                seq,
                None
            )
        )
        self.receivedSecretShare(self._rank, binary_shares[self._rank])
        return secrets_deferred

    def receivedSecretShare(self, peer_rank, share_bin):
        if (self._shares_ready.called or self._received_secrets[peer_rank] is not None):  # Ignore late/unexpected shares
            return
        # Extract subshare
        share = int(share_bin.encode('hex'), 16)
        self._received_secrets[peer_rank] = share
        if (len(filter(lambda s: s is None, self._received_secrets)) == 0):
            self._shares_ready.callback(None)
        return

    def sendPublicValues(self):
        pass

    def receivedPublicValue(self, peer_rank, value):
        pass

    def sendComplaints(self, complain_error):
        pass

    def receivedComplaint(self, blamed_peer, blaming_peer, opt=None):
        pass

    def sendComplaintReaction(self, blaming_peer):
        pass

    def receivedComplaintReaction(self, peer_rank, blaming_peer, reaction):
        pass

    def recombineSecretShare(self, _):
        subshares = [(i + 1, self._received_secrets[i]) for i in xrange(self._n)]
        self._secret_share = shamir.recombine(subshares, self._subshare_t, robust=False)
        return self._secret_share
