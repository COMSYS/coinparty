""" CoinParty - Distributed Key Generation SMPC Value
    Implementation of a distributed key generation scheme secure against a
    1/2-adversary.

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

from struct import Struct as struct

from ActiveSmpcValueWithPublicValue import ActiveSmpcValueWithPublicValue
from .. import Requests as req
import shamir
from base import randint
from ..constants import G, bitcoin_order as standard_order
from ..Bitcoin import serializeEcPoints, deserializeEcPoints
from ..Transaction import ConsistentBroadcastTransaction, EachcastTransaction
from ..log import Logger
from ..exceptions import ComplainError, ThresholdError
log = Logger('dkg')


class NewDkgSmpcValue(ActiveSmpcValueWithPublicValue):
    """ Standard handling for active SMPC values of which the secret share
        shall be secured using Pedersen commitments. """

    COMMIT = 0x00  # Identifier of a commitment public value
    PUBVAL = 0x01  # Identifier of a "real" public value

    def __init__(self, id, index, state):
        super(NewDkgSmpcValue, self).__init__(id, index, state)
        self._H_deferred = None
        try:
            def _set_H(H):
                self._H = H
            self._H_deferred = state.smpc.getValue('H').getPublicValue()
            self._H_deferred.addCallback(_set_H)
        except BaseException:
            self._H = None
        self._commitments = [None] * (self._t + 1)
        self._received_commitments = [None] * self._n
        self._commitment_secrets = [None] * (self._t + 1)
        self._commitments_ready = Deferred()

        self._public_values = [None] * (self._t + 1)
        self._received_public_values = [None] * self._n
        self._public_values_ready = Deferred()

        self._transmitted_secrets = [None] * self._n
        self._received_secrets = [None] * self._n
        self._shares_ready = Deferred()

        self._complaint_timeout = None
        self._complaints_finished = [Deferred(), Deferred()]
        self._complaint_counter = [0] * self._n
        self._protocol_round = 0

    def __statelen__(self):
        return super(NewDkgSmpcValue, self).__statelen__() + 8

    def __getstate__(self):
        state = super(NewDkgSmpcValue, self).__getstate__()
        state += (self._H,)
        state += (self._commitments,)
        state += (self._received_commitments,)
        state += (self._commitment_secrets,)
        state += (self._public_values,)
        state += (self._received_public_values,)
        state += (self._transmitted_secrets,)
        state += (self._received_secrets,)
        return state

    def __setstate__(self, state):
        super(NewDkgSmpcValue, self).__setstate__(state)
        it = iter(state)
        for i in xrange(0, super(NewDkgSmpcValue, self).__statelen__()):
            next(it)
        self._H = next(it)
        self._commitments = next(it)
        self._received_commitments = next(it)
        self._commitment_secrets = next(it)
        self._public_values = next(it)
        self._received_public_values = next(it)
        self._transmitted_secrets = next(it)
        self._received_secrets = next(it)
        self._protocol_round = 2
        self._commitments_ready = Deferred()
        self._commitments_ready.callback(None)
        self._public_values_ready = Deferred()
        self._public_values_ready.callback(None)
        self._shares_ready = Deferred()
        self._shares_ready.callback(None)
        self._complaints_finished = [Deferred(), Deferred()]
        self._complaints_finished[0].callback(None)
        self._complaints_finished[1].callback(None)

    @staticmethod
    def getAlgorithm():
        return 'dkg'

    def initialize(self, order=standard_order, H=None, create_public_value=True):

        self._order = order

        def _fire_deferred(v, d):
            d.callback(None)
            return v

        def _set_round(v, round):
            self._protocol_round = round
            self._secrets_processing = [None] * self._n
            self._public_values_processing = [None] * self._n
            self._complaint_counter = [0] * self._n
            self._open_complaints = [None] * (self._n * self._n)
            self._complaint_naks = [False] * self._n
            return v

        def _wait_for_round_values(_):
            if (self._protocol_round == 0):
                return DeferredList([self._commitments_ready, self._shares_ready])
            elif (self._protocol_round == 1):
                return self._public_values_ready
            else:
                raise RuntimeError('invalid_round')

        def _wait_for_complaints(_):
            if (self._protocol_round >= 2):
                raise RuntimeError('invalid_round')
            return self._complaints_finished[self._protocol_round]

        def _inform_secret_deferreds(v):
            self.informDependentSecretDeferreds()
            return v

        def _inform_public_deferreds(v):
            self.informDependentPublicDeferreds()
            return v

        if (H is not None):  # Override local H if explicitly wished
            self._H = H

        if (H is None and self._H_deferred is not None):
            d = self._H_deferred
        else:
            d = Deferred()
            d.callback(None)

        d.addCallback(_fire_deferred, d=self._secret_share_deferred)
        self._secret_share_deferred.addCallback(_set_round, round=0)
        self._secret_share_deferred.addCallback(self.createSecretShares)
        self._secret_share_deferred.addCallback(self.startCollectingTimeout)
        self._secret_share_deferred.addCallback(self.distributeSharesAndCommitments)
        self._secret_share_deferred.addCallback(_wait_for_round_values)
        self._secret_share_deferred.addCallback(self.verifyReceivedCommitments)
        self._secret_share_deferred.addBoth(self.startComplaintTimeout)
        self._secret_share_deferred.addErrback(self.sendComplaints)
        self._secret_share_deferred.addCallback(self.sendComplaintNaks)
        self._secret_share_deferred.addCallback(_wait_for_complaints)
        self._secret_share_deferred.addCallback(self.disqualifyPlayers)
        self._secret_share_deferred.addCallback(self.setSecretShare)
        self._secret_share_deferred.addCallback(_inform_secret_deferreds)

        if (create_public_value):
            """ Decouple deferreds such that the secret share can be used as
                soon as it is available, before the public value is ready. """
            self._secret_share_deferred.addCallback(_set_round, round=1)
            self._secret_share_deferred.addCallback(_fire_deferred, d=self._public_value_deferred)
            self._public_value_deferred.addCallback(self.startCollectingTimeout)
            self._public_value_deferred.addCallback(self.distributePublicValues)
            self._public_value_deferred.addCallback(_wait_for_round_values)
            self._public_value_deferred.addCallback(self.verifyReceivedPublicValues)
            self._public_value_deferred.addCallback(self.startComplaintTimeout)
            self._public_value_deferred.addErrback(self.sendComplaints)
            self._public_value_deferred.addCallback(self.sendComplaintNaks)
            self._public_value_deferred.addCallback(_wait_for_complaints)
            self._public_value_deferred.addCallback(self.setPublicValue)
            self._public_value_deferred.addCallback(_inform_public_deferreds)
        else:
            self._public_value_deferred.callback(None)
        return self._secret_share_deferred

    def startCollectingTimeout(self, _):
        self._value_timeout = deferLater(
            self._clock, self._timeout_duration,
            self.stopCollecting, None,
            round=self._protocol_round
        )
        self._value_timeout.addErrback(lambda x: None)

    def stopCollecting(self, _, round=None):
        """ State round explicitly as otherwise a delayed timeout call could
            prematurely conclude the subsequent round. """
        if (round is None):  # In this case we are NOT firing a possibly delayed timeout!
            round = self._protocol_round
        if (self._value_timeout is not None and not self._value_timeout.called):
            self._value_timeout.cancel()
            self._value_timeout = None
        if (round == 0):
            if (not self._shares_ready.called):
                self._shares_ready.callback(None)
            if (not self._commitments_ready.called):
                self._commitments_ready.callback(None)
            return
        elif (round == 1):
            if (not self._public_values_ready.called):
                self._public_values_ready.callback(None)
            return
        else:
            raise RuntimeError('invalid_round')

    def startComplaintTimeout(self, v):
        def __kill_open_complaints(_):
            self.abortOpenComplaints()
        self._open_complaint_timeout = deferLater(self._clock, self._timeout_duration, __kill_open_complaints, None)
        self._open_complaint_timeout.addErrback(lambda x: None)
        self._complaint_timeout = deferLater(
            self._clock, self._timeout_duration,
            self.stopComplaintCollecting,
            None, round=self._protocol_round
        )
        self._complaint_timeout.addErrback(lambda x: None)  # Swallow cancellation
        return v

    def stopComplaintCollecting(self, _, round=None):
        def __abort_open_complaint_killer(_):
            if (self._open_complaint_timeout is not None and not self._open_complaint_timeout.called):
                """ Cancelling raises an error that we have to swallow.
                    Furthermore, we have to manually kill the open
                    complaints. """
                self._open_complaint_timeout.cancel()
                self.abortOpenComplaints()

        def __fire(_):
            if (not self._complaints_finished[round].called):
                self._complaints_finished[round].callback(None)
        """ State round explicitly as otherwise a delayed timeout call could
            prematurely conclude the subsequent round. """
        if (round is None):  # In this case we are NOT firing a possibly delayed timeout!
            round = self._protocol_round
        if (round >= 2):
            raise RuntimeError('invalid_round')
        dl = DeferredList(self.getOpenComplaints())
        dl.addCallback(__abort_open_complaint_killer)
        dl.addCallback(__fire)

    def createSecretShares(self, _):
        (shares1, factors1) = shamir.share(randint(self._order), self._n, self._t, self._order, True)
        (shares2, factors2) = shamir.share(randint(self._order), self._n, self._t, self._order, True)
        self._transmitted_secrets = [[shares1[i][1], shares2[i][1]] for i in xrange(0, self._n)]
        self._commitment_secrets = [(factors1[k], factors2[k]) for k in xrange(0, self._t + 1)]
        self._public_values = [factors1[k] * G for k in xrange(0, self._t + 1)]
        self._commitments = [self._public_values[k] + factors2[k] * self._H for k in xrange(0, self._t + 1)]
        return

    def distributeSharesAndCommitments(self, _):
        if (self._protocol_round != 0):
            raise RuntimeError('invalid_round')
        commitments_deferred = self.sendPublicValues()
        secrets_deferred = self.sendSecretShares()
        return DeferredList([commitments_deferred, secrets_deferred])

    def distributePublicValues(self, _):
        if (self._protocol_round != 1):
            raise RuntimeError('invalid_round')
        public_value_deferred = self.sendPublicValues()
        return public_value_deferred

    def sendSecretShares(self):
        if (self._protocol_round == 0):
            """ Use point-to-point connection to send secrets. """
            connected_peers = self._getConnectedPeers()
            seq = self._transactions.getNextSequenceNumber()
            msgs = []
            binary_shares = []
            for r in self.getRankList(connected_peers):
                binary_secret_share_pair = map(lambda x: '{0:0{1}x}'.format(x, 64).decode('hex'), self._transmitted_secrets[r])
                binary_secret_share = \
                    struct('>BB').pack(len(binary_secret_share_pair[0]), len(binary_secret_share_pair[1])) + \
                    binary_secret_share_pair[0] + \
                    binary_secret_share_pair[1]
                binary_shares.append(binary_secret_share)
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
        elif (self._protocol_round == 1):
            d = Deferred()
            d.callback(None)
            return d
        else:
            raise RuntimeError('invalid_round')

    def receivedSecretShare(self, peer_rank, binary_share):
        if (peer_rank not in self._qualified):
            return
        if (self._shares_ready.called or self._received_secrets[peer_rank] is not None or self._protocol_round != 0):  # Ignore late/unexpected shares
            return
        share_lengths = struct('>BB').unpack(binary_share[:2])
        share = [
            int(binary_share[2:(2 + share_lengths[0])].encode('hex'), 16),
            int(binary_share[(2 + share_lengths[0]):(2 + share_lengths[0] + share_lengths[1])].encode('hex'), 16),
        ]
        self._received_secrets[peer_rank] = share
        if (len(filter(lambda s: s is None, self._received_secrets)) == 0):
            self._shares_ready.callback(None)
        return

    def sendPublicValues(self):
        """ Use consistent broadcast to send commitments. """
        connected_peers = self._getConnectedPeers()
        if (self._protocol_round == 0):  # First round: send commitments
            sent_values = chr(self.COMMIT) + serializeEcPoints(self._commitments)
        elif (self._protocol_round == 1):  # Second round: send public value shares
            sent_values = chr(self.PUBVAL) + serializeEcPoints(self._public_values)
        else:
            raise RuntimeError('invalid_round')
        seq = self._transactions.getNextSequenceNumber()
        msg = req.mpcp.encode(
            self._rank,
            seq,
            self._crypters[self._rank],
            self.getAlgorithm(),
            self.getID(),
            self.getIndex(),
            sent_values
        )
        transaction = ConsistentBroadcastTransaction(
            self._rank,
            self._crypters[self._rank],
            connected_peers,
            self._n,
            self._t,
            seq,
            msg
        )
        transaction.defineCallback(req.mpcp, self)
        public_value_deferred = self._transactions.addTransaction(transaction)
        self.receivedPublicValue(self._rank, sent_values)
        return public_value_deferred

    def receivedPublicValue(self, peer_rank, value):
        if (peer_rank not in self._qualified):
            return
        if (ord(value[0]) == NewDkgSmpcValue.COMMIT):
            if (self._commitments_ready.called or self._received_commitments[peer_rank] is not None):  # Ignore late/unexpected shares
                return
            self._received_commitments[peer_rank] = deserializeEcPoints(value[1:])
            if (len(filter(lambda c: c is None, self._received_commitments)) == 0):
                self._commitments_ready.callback(None)
            return
        elif (ord(value[0]) == NewDkgSmpcValue.PUBVAL):
            if (self._public_values_ready.called or self._received_public_values[peer_rank] is not None):  # Ignore late/unexpected shares
                return
            self._received_public_values[peer_rank] = deserializeEcPoints(value[1:])

            if (len(filter(lambda p: p is None, [self._received_public_values[i] for i in self._qualified])) == 0):
                self._public_values_ready.callback(None)
            return
        else:
            raise RuntimeError('invalid_public_value')

    def verifyCommitment(self, share, share_owner, commitment_owner):
        j = share_owner + 1
        i = commitment_owner
        check1 = share[0] * G + share[1] * self._H
        check2_summands = [(j**k) * self._received_commitments[i][k] for k in xrange(0, self._t + 1)]
        check2 = reduce(lambda x, y: x + y, check2_summands)
        return (check1 == check2)

    def verifyReceivedCommitments(self, _):
        secret_shares = self._received_secrets
        commitments = self._received_commitments
        to_blame = []
        for i in xrange(0, len(commitments)):
            if (commitments[i] is None or secret_shares[i] is None or len(filter(lambda x: x is not None, commitments[i])) != self._t + 1):
                log.debug('Missing commitment from player ' + str(i) + '.')
                to_blame.append(i)
            else:
                if (not self.verifyCommitment(secret_shares[i], self._rank, i)):
                    log.debug('Commitment check failed.')
                    to_blame.append(i)
        if (len(to_blame) > 0):
            raise ComplainError('complaints', to_blame)
        return

    def verifyReceivedPublicValues(self, _):
        secret_shares = self._received_secrets
        public_values = self._received_public_values
        to_blame = []
        for i in self._qualified:
            if (public_values[i] is None or secret_shares[i] is None or len(filter(lambda x: x is not None, public_values[i])) != self._t + 1):
                log.debug('Missing public value from player ' + str(i) + '(' + str(self._id) + ', ' + str(self._index) + ').')
                to_blame.append(i)
            else:
                if (not self.verifyPublicValue(secret_shares[i][0], self._rank, i)):
                    log.debug('Public value check failed.')
                    to_blame.append(i)
        if (len(to_blame) > 0):
            # self.disqualifyPlayerSet(to_blame) # Locally disqualify players that I am about to accuse
            raise ComplainError('complaints', to_blame)
        return

    def verifyPublicValue(self, share, share_owner, public_value_owner):
        j = share_owner + 1
        i = public_value_owner
        check1 = share * G
        check2_summands = [(j**k) * self._received_public_values[i][k] for k in xrange(0, self._t + 1)]
        check2 = reduce(lambda x, y: x + y, check2_summands)
        return (check1 == check2)

    def sendComplaints(self, complain_error):
        # Locally disqualify players that will be blamed by this peer
        if (not isinstance(complain_error.value, ComplainError)):
            log.error('Unexpected error: ' + str(complain_error.getErrorMessage()))
            return
        to_blame = complain_error.value.ranks
        for p in to_blame:
            self.markPlayer(p)
        qual_size = len(self._qualified) - len([m for m in self._disqualify_marked if m])

        connected_peers = self._getConnectedPeers()

        # Blame the peers
        deferreds = []
        for i in xrange(0, len(to_blame)):
            self.setOpenComplaint(self._rank, to_blame[i])
            seq = self._transactions.getNextSequenceNumber()
            if (self._protocol_round == 0):
                opt = None
            elif (self._protocol_round == 1):
                opt = self._received_secrets[i]
            else:
                raise RuntimeError('invalid_round')
            msg = req.comp.encode(self._rank, seq, self._crypters[self._rank], self.getAlgorithm(), self.getID(), self.getIndex(), to_blame[i], opt)
            transaction = ConsistentBroadcastTransaction(
                self._rank,
                self._crypters[self._rank],
                connected_peers,
                self._n,
                self._t,
                seq,
                msg
            )
            broadcast_deferred = self._transactions.addTransaction(transaction)
            transaction.defineCallback(req.comp, self)
            deferreds.append(broadcast_deferred)

        if (qual_size <= self._t):
            raise ThresholdError('too_few_players')
        return DeferredList(deferreds)

    def receivedComplaint(self, blamed_peer, blaming_peer, opt=None):
        if (blaming_peer not in self._qualified):
            return
        self.setOpenComplaint(blaming_peer, blamed_peer)
        if (self._protocol_round == 0):
            if (blamed_peer == self._rank):  # Am I being blamed? React!
                return self.sendComplaintReaction(blaming_peer)
            else:
                self._complaint_counter[blamed_peer] += 1
                if (self._complaint_counter[blamed_peer] > self._t):
                    self.markPlayer(blamed_peer)
                return
        elif (self._protocol_round == 1):
            if (blamed_peer == self._rank):  # In this case, we can't do anything
                return
            else:
                # ToDo: Implement
                print('Peer ' + str(self._rank) + ': I should run pedersen reconstruction, but no.')
                return
        else:
            raise RuntimeError('invalid_round')

    def sendComplaintReaction(self, blaming_peer):
        connected_peers = self._getConnectedPeers()
        seq = self._transactions.getNextSequenceNumber()
        secret_share = self._transmitted_secrets[blaming_peer]
        msg = req.cmpr.encode(self._rank, seq, self._crypters[self._rank], self.getAlgorithm(), self.getID(), self.getIndex(), blaming_peer, secret_share)
        transaction = ConsistentBroadcastTransaction(
            self._rank,
            self._crypters[self._rank],
            connected_peers,
            self._n,
            self._t,
            seq,
            msg
        )
        broadcast_deferred = self._transactions.addTransaction(transaction)
        transaction.defineCallback(req.cmpr, self)
        self.closeOpenComplaint(blaming_peer, self._rank)
        return broadcast_deferred

    def receivedComplaintReaction(self, peer_rank, blaming_peer, reaction):
        if (peer_rank not in self._qualified):
            return
        if (self._protocol_round != 0):
            return
        if (not self.verifyCommitment(reaction, blaming_peer, peer_rank)):
            self.markPlayer(peer_rank)
        self.closeOpenComplaint(blaming_peer, peer_rank)
        return

    def disqualifyPlayers(self, _):
        disqualify_players = filter(lambda x: self._disqualify_marked[x], self._qualified)
        number_remaining_players = self.disqualifyPlayerSet(disqualify_players)
        if (number_remaining_players <= self._t):
            raise ThresholdError('too_few_players')
        return

    def setSecretShare(self, _):
        shares = [self._received_secrets[i][0] for i in self._qualified]
        coshares = [self._received_secrets[i][1] for i in self._qualified]
        self._secret_share = reduce(lambda x, y: (x + y) % self._order, shares)
        self._secret_coshare = reduce(lambda x, y: (x + y) % self._order, coshares)
        return self._secret_share

    def setPublicValue(self, _):
        public_values = [self._received_public_values[i][0] for i in self._qualified]
        self._public_value = reduce(lambda x, y: (x + y), public_values)
        return self._public_value
