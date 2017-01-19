""" CoinParty - Base State
    A meta state object, acting as a collection of sub-states.
    Also, we have a collection of states.

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

from ShufflingState import ShufflingState
from InputPeerState import InputPeerState
from CommitmentState import CommitmentState
from CryptoState import CryptoState
from MixnetState import MixnetState

from ..low.smpc.SmpcStore import SmpcStore

from twisted.internet.defer import Deferred
from twisted.internet import reactor
from ..low.Transaction import TransactionStore
import re

from decimal import Decimal, getcontext
getcontext().prec = 8


class BaseState(object):
    """ Provide a shared state object to allow for synchronization between the
        different phases of the mixing. """

    """ Set up a mixing state and its sub-states. """
    def __init__(self, rank, mixnet_id, mixnet_size, mixing_window_mins=0.5, clock=reactor):
        self._shutdown_flag = False
        self._error_deferred = Deferred()
        self.rank = rank
        self._bitcoin_value = Decimal(str(0.1)) + Decimal('0.00000000')
        self._mixing_window_mins = mixing_window_mins
        self._clock = clock

        self.mixnet = MixnetState(mixnet_id, mixnet_size, rank)
        self.input = InputPeerState(rank, mixnet_size)
        self.commit = CommitmentState()
        self.shuffle = ShufflingState(mixnet_size)
        self.crypto = CryptoState()

        self.smpc = SmpcStore()

        self._in_streaming_phase = False
        self._mixing_concluded = False

        self._last_block = None
        self._p2p_client = None
        self._p2p_server = None

        self._web_blocked = True
        self.transactions = TransactionStore()
        self.dummy_deferred = Deferred()

    @staticmethod
    def getTransactionFee():
        return Decimal("0.0001")

    def getClock(self):
        return self._clock

    def enterStreamingPhase(self):
        self._in_streaming_phase = True

    def isInStreamingPhase(self):
        return self._in_streaming_phase

    def concludeMixing(self):
        self._in_streaming_phase = False
        self._mixing_concluded = True

    def isMixingConcluded(self):
        return self._mixing_concluded

    def getBitcoinValue(self):
        return self._bitcoin_value


# Blocking of the web interface

    def blockWebServer(self):
        self._web_blocked = True

    def unblockWebServer(self):
        self._web_blocked = False

    def webServerBlocked(self):
        return self._web_blocked

    def getFormattedReport(self, format, ack_string, nak_string, input_peer_id):
        report = ''
        for peer in sorted([self.mixnet.getMixpeers()[self.rank]] + self.mixnet.getOtherMixpeers(), key=lambda p: p['id']):
            input_peer = self.input.getInputPeer('id', input_peer_id)
            line = re.sub('\#id\#', peer['id'], format)
            line = re.sub('\#ack\#', ack_string if input_peer['report'][peer['rank']] else nak_string, line)
            line = re.sub('\#url\#', peer['web'], line)
            line = re.sub('\#sid\#', input_peer['session_id'], line)
            line = re.sub('\#pin\#', str(input_peer['used_secret']), line)
            report += line
        return report

    def setLastBlockHash(self, hash):
        self._last_block = hash
        return

    def getLastBlockHash(self):
        if (self._last_block is not None):
            return self._last_block
        else:
            raise KeyError('Last block hash is not known!')

    def getUnseenTransactionEscrows(self):
        return self.input._unseen_tx_escrow_addresses

    def getUnconfirmedTransactions(self):
        return self.input._unconfirmed_transactions

    def foundCommitment(self, txid):
        input_peer = self.input.getInputPeer('txid', txid)
        if (input_peer is None):
            raise ValueError('txid_not_found')
        index = self.input._unconfirmed_transactions.index(txid)
        del self.input._unconfirmed_transactions[index]
        input_peer['tx_confirmed'] = True
        return

    def allPaymentsReceived(self):
        if (not self.input.inputPeersFrozen()):
            return False
        result = True
        for input_peer in self.input.getAssignedEscrows():
            if (not input_peer['tx_confirmed']):
                result = False
        return result

    def setP2pServer(self, p2p_server, p2p_server_deferred):
        self._p2p_server = p2p_server
        self._p2p_server_deferred = p2p_server_deferred

    def getP2pServer(self):
        return self._p2p_server

    def getP2pServerDeferred(self):
        return self._p2p_server_deferred

    def setP2pClient(self, p2p_client, p2p_client_deferred):
        self._p2p_client = p2p_client
        self._p2p_client_deferred = p2p_client_deferred

    def getP2pClient(self):
        return self._p2p_client

    def getP2pClientDeferred(self):
        return self._p2p_client_deferred

    def setShutdownFlag(self):
        self._shutdown_flag = True

    def getErrorDeferred(self):
        return self._error_deferred

    def triggerErrorDeferred(self, exception):
        if (not self._error_deferred.called):
            self._error_deferred.errback(exception)


class MixingPeerState():

    _using_testnet = True

    def __init__(self, states=[]):
        self._array = states
        self._history = []
        self._id = None
        self._pubkey = None
        self._prvkey = None
        self._crypter = None
        self._webserver = None
        return

    def removeState(self, state):
        del self._array[self._array.index(state)]

    def setGlobalConfig(self, global_config):
        self._using_testnet = global_config.as_bool('testnet')
        return

    def getState(self, mixnet_id):
        return next((state for state in self._array if (state.mixnet.getMixnetID() == mixnet_id)), None)

    def findState(self, txid):
        return next((state for state in self._array if (state.input.getInputPeer('txid', txid) is not None)), None)

    def setMixpeerID(self, id):
        self._id = id

    def getMixpeerID(self):
        return self._id

    def usingTestnet(self):
        return self._using_testnet

    def getFormattedMixnetList(self, format_good, format_bad):
        list = ''
        for state in self._array:
            line = re.sub('\#id\#', state.mixnet.getMixnetID(), format_good if (not state.webServerBlocked()) else format_bad)
            list += line
        return list

    def getStates(self):
        return self._array

    def appendState(self, state):
        self._array.append(state)
        return

    def findInputPeer(self, session_id):
        """ Search for a session ID among all states.
            This assumes that session IDs are "sufficiently unique". """
        for state in self._array:
            input_peer = state.input.getInputPeer('session_id', session_id)
            if (input_peer is not None):
                return {'input_peer' : input_peer, 'state' : state, 'history' : False}
        for state in self._history:
            input_peer = state.input.getInputPeer('session_id', session_id)
            if (input_peer is not None):
                return {'input_peer' : input_peer, 'state' : state, 'history' : True}
        return {'input_peer' : None, 'state' : None, 'history' : False}

    def getFormattedVerifyList(self, format, cookies):
        list = ''

        for cookie in cookies:
            mixnet_id = cookie
            session_id = cookies[cookie]
            # Check for validity:
            state = self.findInputPeer(session_id)['state']
            if (state is None or mixnet_id != state.mixnet.getMixnetID()):
                line = re.sub('\#id\#', 'None', format)
                line = re.sub('\#sid\#', '', line)
            else:
                line = re.sub('\#id\#', mixnet_id, format)
                line = re.sub('\#sid\#', session_id, line)
            list += line
        return list

    def renewState(self, mixnet_id):
        state = self.getState(mixnet_id)
        new_state = BaseState(
            state.mixnet.getRank(),
            state.mixnet.getMixnetID(),
            state.mixnet.getMixnetSize()
        )
        state_index = self._array.index(state)
        del self._array[state_index]
        self.appendState(new_state)
        self._history.append(state)

    def setWebServer(self, webserver):
        self._webserver = webserver

    def getWebServer(self):
        return self._webserver


mstate = MixingPeerState()
