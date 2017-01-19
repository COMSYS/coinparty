""" CoinParty - Active SMPC Value
    An abstract class for SMPC values that require communication between peers.

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

from SmpcValue import SmpcValue
from ..Transaction import BroadcastTransaction
from ..exceptions import AbstractClassError
from .. import Requests as req


class ActiveSmpcValue(SmpcValue):
    """ Define an interface for SMPC values that require communication
        between peers. """

#####################################################################
#
#       Parameters
#
#####################################################################

    _timeout_duration = 60

#####################################################################
#
#       Helpers
#
#####################################################################

    def __init__(self, id, index, state):
        super(ActiveSmpcValue, self).__init__(state)
        self._id = id
        self._index = index
        self._rank = state.mixnet.getRank()
        self._getConnectedPeers = state.mixnet.getConnectedMixpeers
        self._transactions = state.transactions
        self._complaint_naks = [False] * self._n
        self._open_complaint_timeout = None
        self._crypters = []
        for i in xrange(state.mixnet.getMixnetSize()):
            self._crypters.append(state.crypto.getCrypter() if i == self._rank else state.mixnet.getMixpeer(i)['crypt'])
        """ In the worst case, each peer complains against each other peer.
            Should be seen as 2D-array in which _open_complaints[i][j] denotes
            that i complains against j. """
        self._open_complaints = [None] * (self._n * self._n)
        self._disqualify_marked = [False] * self._n
        self._qualified = xrange(0, self._n)
        self._clock = state.getClock()

    def __statelen__(self):
        return super(ActiveSmpcValue, self).__statelen__() + 4

    def __getstate__(self):
        state = super(ActiveSmpcValue, self).__getstate__()
        state += (self._id,)
        state += (self._index,)
        state += (self._rank,)
        state += (self._qualified,)
        return state

    def __setstate__(self, state):
        super(ActiveSmpcValue, self).__setstate__(state)
        it = iter(state)
        for i in xrange(0, super(ActiveSmpcValue, self).__statelen__()):
            next(it)
        self._id = next(it)
        self._index = next(it)
        self._rank = next(it)
        self._qualified = next(it)

    def getRankList(self, connected_peers=None):
        return xrange(max(map(lambda x: x['rank'], self._getConnectedPeers() if connected_peers is None else connected_peers) + [self._rank]) + 1)

    def getID(self):
        return self._id

    def getIndex(self):
        return self._index

    @staticmethod
    def getAlgorithm():
        return AbstractClassError()

#####################################################################
#
#       Secret Share Methods
#
#####################################################################

    def sendSecretShares(self):
        """ Distribute internal secret shares to their recipients. """
        raise AbstractClassError()

    def receivedSecretShare(self, peer_rank, share):
        """ Store secret share received from another peer. """
        raise AbstractClassError()

#####################################################################
#
#       Public Value Methods
#
#####################################################################

    def sendPublicValues(self):
        """ Broadcast public values to all peers. """
        raise AbstractClassError()

    def receivedPublicValue(self, peer_rank, value):
        """ Store public values received from another peer. """
        raise AbstractClassError()

#####################################################################
#
#       Complaint Methods
#
#####################################################################

    def sendComplaints(self, complain_error):
        """ Broadcast complaints to all peers. """
        raise AbstractClassError()

    def receivedComplaint(self, peer_rank, blamed_rank, opt=None):
        """ Check a received complaint and decide whether blamed_peer should
            be disqualified locally or not. """
        raise AbstractClassError()

    def sendComplaintReaction(self, blaming_peer):
        """ React to any complaint that blamed this peer. """
        raise AbstractClassError()

    def receivedComplaintReaction(self, peer_rank, blaming_peer, reaction):
        """ Process a received complaint reaction.
            Decide whether the reaction is sufficient to un-disqualify the
            blamed peer agein. """
        raise AbstractClassError()

    def sendComplaintNaks(self, _):
        """ Explicitly state that no complaints will be sent by this peer.
            Sole purpose of this is to bypass waiting periods in entirely
            honest protocol runs. """
        connected_peers = self._getConnectedPeers()
        seq = self._transactions.getNextSequenceNumber()
        msg = req.ncmp.encode(self._rank, seq, self._crypters[self._rank], self.getAlgorithm(), self.getID(), self.getIndex())
        broadcast_deferred = self._transactions.addTransaction(
            BroadcastTransaction(
                self._rank,
                connected_peers,
                msg,
                seq,
                None
            )
        )
        self.receivedComplaintNak(self._rank)
        return broadcast_deferred

    def receivedComplaintNak(self, peer_rank):
        """ Store information that peer_rank will not complain currently. """
        self._complaint_naks[peer_rank] = True
        if (reduce(lambda x, y: x and y, [self._complaint_naks[i] for i in self._qualified]) is True):
            self.stopComplaintCollecting(None)

    def stopComplaintCollecting(self, _):
        raise AbstractClassError()

    def markPlayer(self, player):
        self._disqualify_marked[player] = True

    def unmarkPlayer(self, player):
        self._disqualify_marked[player] = False

    def disqualifyMarkedPlayers(self):
        return self.disqualifyPlayerSet(filter(lambda i: self._disqualify_marked[i], xrange(0, self._n)))

    def disqualifyPlayerSet(self, set):
        self._qualified = filter(lambda x: x not in set, self._qualified)
        return len(self._qualified)

    def getQualifiedPlayerSet(self):
        return self._qualified

    def setOpenComplaint(self, blaming_peer, blamed_peer):
        index = blaming_peer * self._n + blamed_peer
        if (self._open_complaints[index] is None):
            self._open_complaints[index] = Deferred()
            self._open_complaints[index].addErrback(lambda x: None)

    def closeOpenComplaint(self, blaming_peer, blamed_peer):
        index = blaming_peer * self._n + blamed_peer
        if (self._open_complaints[index] is not None and not self._open_complaints[index].called):
            self._open_complaints[index].callback(None)

    def getOpenComplaints(self):
        return [d for d in self._open_complaints if d is not None]

    def abortOpenComplaints(self):
        for d in [d for d in self._open_complaints if d is not None]:
            d.cancel()
