""" CoinParty - JfDKG SMPC Value
    An implementation of JFDKG, which is used to generate the value H,
    which is required for our distributed key generation.

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

from twisted.internet.defer import Deferred, DeferredList
from twisted.internet.task import deferLater

from ActiveSmpcValueWithPublicValue import ActiveSmpcValueWithPublicValue
import shamir
from base import randint
from .. import Requests as req
from ..constants import G, bitcoin_order as standard_order
from ..Bitcoin import serializeEcPoints, deserializeEcPoints
from ..Transaction import ConsistentBroadcastTransaction, EachcastTransaction
from ..log import Logger
from ..exceptions import ComplainError, ThresholdError
log = Logger('jfdkg')


class JfDkgSmpcValue(ActiveSmpcValueWithPublicValue):

    def __init__(self, id, index, state):
        super(JfDkgSmpcValue, self).__init__(id, index, state)
        self._public_verification_values = [None] * (self._t + 1)
        self._public_values = [None] * (self._t + 1)
        self._received_public_values = [None] * self._n
        self._secret_factors = [None] * (self._t + 1)
        self._transmitted_secrets = [None] * self._n
        self._received_secrets = [None] * self._n
        self._public_values_ready = Deferred()
        self._shares_ready = Deferred()
        self._complaints_finished = Deferred()
        self._complaint_timeout = None
        self._value_timeout = None

    def __statelen__(self):
        return super(JfDkgSmpcValue, self).__statelen__() + 6

    def __getstate__(self):
        state = super(JfDkgSmpcValue, self).__getstate__()
        state += (self._public_verification_values,)
        state += (self._public_values,)
        state += (self._received_public_values,)
        state += (self._secret_factors,)
        state += (self._transmitted_secrets,)
        state += (self._received_secrets,)
        return state

    def __setstate__(self, state):
        super(JfDkgSmpcValue, self).__setstate__(state)
        it = iter(state)
        for i in xrange(0, super(JfDkgSmpcValue, self).__statelen__()):
            next(it)
        self._public_verification_values = next(it)
        self._public_values = next(it)
        self._received_public_values = next(it)
        self._secret_factors = next(it)
        self._transmitted_secrets = next(it)
        self._received_secrets = next(it)
        self._public_values_ready = Deferred()
        self._public_values_ready.callback(None)
        self._shares_ready = Deferred()
        self._shares_ready.callback(None)
        self._complaints_finished = Deferred()
        self._complaints_finished.callback(None)

    @staticmethod
    def getAlgorithm():
        return 'jfdkg'

    def initialize(self, order=standard_order):
        self._order = order

        def _wait_for_complaints(_):
            return self._complaints_finished

        def _wait_for_values(_):
            return DeferredList([self._public_values_ready, self._shares_ready])

        def _fire_public_value(value):
            self._public_value_deferred.callback(self._public_value)
            return value

        def _inform_dependent_deferreds(value):
            self.informDependentSecretDeferreds()
            self.informDependentPublicDeferreds()
            return value

        self._secret_share_deferred.addCallback(self.createPrivateKeyShare)
        self._secret_share_deferred.addCallback(self.startCollectingTimeout)
        self._secret_share_deferred.addCallback(self.distributeSharesAndPublicValues)
        self._secret_share_deferred.addCallback(_wait_for_values)
        self._secret_share_deferred.addCallback(self.verifyReceivedShares)
        self._secret_share_deferred.addBoth(self.startComplaintTimeout)
        self._secret_share_deferred.addErrback(self.sendComplaints)
        self._secret_share_deferred.addCallback(self.sendComplaintNaks)
        self._secret_share_deferred.addCallback(_wait_for_complaints)
        self._secret_share_deferred.addCallback(self.disqualifyPlayers)
        self._secret_share_deferred.addCallback(self.computePublicValue)
        self._secret_share_deferred.addCallback(_fire_public_value)
        self._secret_share_deferred.addCallback(_inform_dependent_deferreds)

        self._secret_share_deferred.callback(None)
        return self._secret_share_deferred

    def getPublicVerificationValues(self):
        return self._public_verification_values

    def startCollectingTimeout(self, v):
        self._value_timeout = deferLater(self._clock, self._timeout_duration, self.stopCollecting, None)
        self._value_timeout.addErrback(lambda x: None)
        return v

    def stopCollecting(self, _):
        if (self._value_timeout is not None and not self._value_timeout.called):
            self._value_timeout.cancel()
        if (not self._shares_ready.called):
            self._shares_ready.callback(None)
        if (not self._public_values_ready.called):
            self._public_values_ready.callback(None)

    def startComplaintTimeout(self, v):
        def __kill_open_complaints(_):
            self.abortOpenComplaints()
        self._open_complaint_timeout = deferLater(self._clock, self._timeout_duration, __kill_open_complaints, None)
        self._open_complaint_timeout.addErrback(lambda x: None)
        self._complaint_timeout = deferLater(self._clock, self._timeout_duration, self.stopComplaintCollecting, None)
        self._complaint_timeout.addErrback(lambda x: None)
        return v

    def stopComplaintCollecting(self, _):
        def __abort_open_complaint_killer(_):
            if (self._open_complaint_timeout is not None and not self._open_complaint_timeout.called):
                """ Cancelling raises an error that we have to swallow.
                    Furthermore, we have to manually kill the open
                    complaints. """
                self._open_complaint_timeout.cancel()
                self.abortOpenComplaints()

        def __fire(_):
            if (not self._complaints_finished.called):
                self._complaints_finished.callback(None)
        if (self._complaint_timeout != None and not self._complaint_timeout.called):
            self._complaint_timeout.cancel()
        dl = DeferredList(self.getOpenComplaints())
        dl.addCallback(__abort_open_complaint_killer)
        dl.addCallback(__fire)

    def createPrivateKeyShare(self, _):
        """ Create a sharing of a random value. """
        (shares, factors) = shamir.share(randint(self._order), self._n, self._t, self._order, True)
        self._transmitted_secrets = [shares[i][1] for i in xrange(0, self._n)]
        self._secret_factors = [factors[k] for k in xrange(0, self._t + 1)]
        self._public_values = [factors[k] * G for k in xrange(0, self._t + 1)]
        return

    def distributeSharesAndPublicValues(self, _):
        public_value_deferred = self.sendPublicValues()
        secrets_deferred = self.sendSecretShares()
        return DeferredList([public_value_deferred, secrets_deferred])

    def sendSecretShares(self):
        """ Use point-to-point connection to send secrets. """
        connected_peers = self._getConnectedPeers()
        seq = self._transactions.getNextSequenceNumber()
        msgs = []
        # Compute binary presentation of secret shares
        binary_shares = ['{0:0{1}x}'.format(self._transmitted_secrets[r], 64).decode('hex') for r in self.getRankList(connected_peers)]
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
        # Compute binary presentation of secret share
        self.receivedSecretShare(self._rank, binary_shares[self._rank])
        return secrets_deferred

    def receivedSecretShare(self, peer_rank, binary_share):
        if (self._shares_ready.called or self._received_secrets[peer_rank] is not None):  # Ignore late/unexpected shares
            return
        share = int(binary_share.encode('hex'), 16)
        self._received_secrets[peer_rank] = share
        if (len(filter(lambda s: s is None, self._received_secrets)) == 0):
            self._shares_ready.callback(None)
        return

    def sendPublicValues(self):
        """ Use consistent broadcast to send commitments. """
        connected_peers = self._getConnectedPeers()
        public_values_serialized = serializeEcPoints(self._public_values)
        seq = self._transactions.getNextSequenceNumber()
        msg = req.mpcp.encode(
            self._rank,
            seq,
            self._crypters[self._rank],
            self.getAlgorithm(),
            self.getID(),
            self.getIndex(),
            public_values_serialized
        )
        public_value_deferred = self._transactions.addTransaction(
            ConsistentBroadcastTransaction(
                self._rank,
                self._crypters[self._rank],
                connected_peers,
                self._n,
                self._t,
                seq,
                msg
            )
        )

        self.receivedPublicValue(self._rank, public_values_serialized)
        return public_value_deferred

    def receivedPublicValue(self, peer_rank, value):
        if (self._public_values_ready.called or self._received_public_values[peer_rank] is not None):  # Ignore late/unexpected shares
            return
        self._received_public_values[peer_rank] = deserializeEcPoints(value)
        if (len(filter(lambda c: c is None, self._received_public_values)) == 0):
            self._public_values_ready.callback(None)
        return

    def verifyReceivedShares(self, _):
        public_shares = self._received_public_values
        secret_shares = self._received_secrets
        to_blame = []
        for i in xrange(0, len(public_shares)):
            if (public_shares[i] is None or secret_shares[i] is None or len(filter(lambda x: x is not None, public_shares[i])) < self._t + 1):

                log.debug('Missing share from player ' + str(i) + '.')
                to_blame.append(i)
            else:
                if (not self.verifyShare(secret_shares[i], i, self._rank)):
                    log.debug('Share check failed.')
                    to_blame.append(i)
        if (len(to_blame) > 0):
            raise ComplainError('jfdkg_complaints', to_blame)
        return

    def verifyShare(self, share, sending_rank, checked_rank):
        j = checked_rank + 1
        public_shares = self._received_public_values[sending_rank]
        check1_share = share * G
        check2_summands = [(j**k) * public_shares[k] for k in xrange(0, self._t + 1)]
        check2_share = reduce(lambda x, y: x + y, check2_summands)
        return (check1_share == check2_share)

    def sendComplaints(self, complain_error):
        if (not isinstance(complain_error.value, ComplainError)):
            log.error('Unexpected error: ' + str(complain_error.getErrorMessage()))
            log.error('Traceback:\n' + str(complain_error.getTraceback()))
            return complain_error
        to_blame = complain_error.value.ranks
        # Locally disqualify players that will be blamed by this peer
        qual_size = self.disqualifyPlayerSet(to_blame)

        connected_peers = self._getConnectedPeers()

        # Blame the peers
        deferreds = []
        for i in xrange(0, len(to_blame)):
            self.setOpenComplaint(self._rank, to_blame[i])
            seq = self._transactions.getNextSequenceNumber()
            msg = req.comp.encode(self._rank, seq, self._crypters[self._rank], self.getAlgorithm(), self.getID(), self.getIndex(), to_blame[i])
            broadcast_deferred = self._transactions.addTransaction(
                ConsistentBroadcastTransaction(
                    self._rank,
                    self._crypters[self._rank],
                    connected_peers,
                    self._n,
                    self._t,
                    seq,
                    msg
                )
            )
            deferreds.append(broadcast_deferred)

        if (qual_size <= self._t):
            raise ThresholdError('too_few_players')
        return DeferredList(deferreds)

    def receivedComplaint(self, blamed_peer, blaming_peer, opt=None):
        self.setOpenComplaint(blaming_peer, blamed_peer)
        if (blamed_peer == self._rank):  # Am I being blamed? React!
            return self.sendComplaintReaction(blaming_peer)
        else:
            self.markPlayer(blamed_peer)

    def sendComplaintReaction(self, blaming_peer):
        connected_peers = self._getConnectedPeers()
        seq = self._transactions.getNextSequenceNumber()
        secret_share = self._transmitted_secrets[blaming_peer]
        msg = req.cmpr.encode(self._rank, seq, self._crypters[self._rank], self.getAlgorithm(), self.getID(), self.getIndex(), blaming_peer, secret_share)
        broadcast_deferred = self._transactions.addTransaction(
            ConsistentBroadcastTransaction(
                self._rank,
                self._crypters[self._rank],
                connected_peers,
                self._n,
                self._t,
                seq,
                msg
            )
        )
        self.closeOpenComplaint(blaming_peer, self._rank)
        return broadcast_deferred

    def receivedComplaintReaction(self, peer_rank, blaming_peer, reaction):
        if (self.verifyShare(reaction, peer_rank, blaming_peer)):
            self.unmarkPlayer(peer_rank)
        self.closeOpenComplaint(blaming_peer, peer_rank)
        return

    def disqualifyPlayers(self, _):
        disqualify_players = filter(lambda x: self._disqualify_marked[x], self._qualified)
        number_remaining_players = self.disqualifyPlayerSet(disqualify_players)
        if (number_remaining_players <= self._t):
            raise ThresholdError('too_few_players')
        return

    def computePublicValue(self, _):
        """ Determine secret_share. """
        qualified_secret_shares = [self._received_secrets[i] for i in self._qualified]
        self._secret_share = reduce(lambda x, y: (x + y) % self._order, qualified_secret_shares)

        """ Determine public verification information. """
        for k in xrange(0, self._t + 1):
            self._public_verification_values[k] = \
                reduce(lambda x, y: x + y, [self._received_public_values[i][k] for i in self._qualified])

        """ Determine public value. """
        qualified_public_values = [self._received_public_values[i][0] for i in self._qualified]
        self._public_value = reduce(lambda x, y: x + y, qualified_public_values)
        return self._secret_share  # We return this as this function is part of the initialize() callback chain
