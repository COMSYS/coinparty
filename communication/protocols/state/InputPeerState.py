""" CoinParty - Input Peer State
    State information related to users submitting their funds for a mixing
    operation.

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


class InputPeerState():
    """ Define conditions for the range of accepted numbers of input peers. """

    def __init__(self, rank, mixnet_size):

        # Escrow address assignment
        self._rank = rank
        self._escrow_next_free_slot = self._rank
        self._mixnet_size = mixnet_size
        self._escrow_addresses = []
        self._session_errors = []
        self._encrypted_output_addresses = []
        self._partially_decrypted_addresses = []
        self._number_peers = 0
        self._input_peers_frozen = False
        self._assigned_escrows = None

        self._freezing_deferred = Deferred()
        self._freezing_deferred.addCallback(self.determineAssignedEscrows)

        self._output_deferred = Deferred()

        """ Ordered list of those escrow addresses that did not yet occur in a transaction. """
        self._unseen_tx_escrow_addresses = []
        self._unconfirmed_transactions = []

    def getFreezingDeferred(self):
        return self._freezing_deferred

    def _getLowestFreeSlot(self):
        if (self._escrow_next_free_slot >= len(self._escrow_addresses)):
            return None
        else:
            index = self._escrow_next_free_slot
            self._escrow_next_free_slot += self._mixnet_size
            return index

    def getInputPeer(self, key, value):
        try:
            if (key == 'id'):
                input_peer = self._escrow_addresses[value]
            else:
                input_peer = next((i for i in self._escrow_addresses if i[key] == value), None)
        except:
            input_peer = None
        return input_peer

    def addInputPeer(self):
        index = self._getLowestFreeSlot()
        if (index is not None):
            escrow = self._escrow_addresses[index]
            escrow['flagged'] = True
            self._unseen_tx_escrow_addresses.append(escrow['address'])
            self._number_peers += 1
            return escrow
        else:
            return None

    def determineAssignedEscrows(self, _):
        self._input_peers_frozen = True
        self._assigned_escrows = [escrow for escrow in self._escrow_addresses if (escrow['flagged'])]
        if (self._rank == 0):
            self._partially_decrypted_addresses = [a for a in self._encrypted_output_addresses]
        else:
            self._partially_decrypted_addresses = [None] * len(self._assigned_escrows)
        return self._assigned_escrows

    def storeGeneratedEscrow(self, index, public_key, bitcoin_address):
        self._escrow_addresses.append({
            'id'           : index,
            'address'      : bitcoin_address,
            'output'       : None,  # Hold assigned decrypted output address
            'pubkey'       : public_key,
            'txid'         : None,  # Transaction ID from commitment transaction
            'tx_confirmed' : False,  # States whether the transaction has been confirmed sufficiently often
            'session_id'   : None,
            'flagged'      : False,
            'pending'      : [],
            'report'       : [False] * self._mixnet_size,
            'used_secret'  : None,
            'secret_deferred' : Deferred(),
            'split'        : None,
            'hash_share'   : Deferred()
        })
        return

    def getAssignedEscrows(self):
        if (self.inputPeersFrozen()):
            return self._assigned_escrows
        else:
            return [escrow for escrow in self._escrow_addresses if (escrow['flagged'])]

    def getNumberInputPeers(self):
        return self._number_peers

    def getSessionErrors(self, session_id):
        return next((error for error in self._session_errors if (error['session_id'] == session_id)), None)

    def createSessionError(self, session_id, rank, error):
        session_error = self.getSessionErrors(session_id)
        if (session_error is None):
            session_error = {
                'session_id' : session_id,
                'errors'     : []
            }
            self._session_errors.append(session_error)
        session_error['errors'].append({'rank' : rank, 'error' : error})
        return

    def createSessionErrors(self, session_id, rank, errors):
        for error in errors:
            self.createSessionError(session_id, rank, error)

    def inputPeersFrozen(self):
        return self._input_peers_frozen

    def flagInputPeer(self, rank, escrow, session_id, encrypted_output_address):

        if (session_id is None):
            # Cannot create session error for nonexistant session
            return (False, 'session_id_missing')

        if (rank is None):
            self.createSessionError(session_id, None, 'rank_missing')
            return (False, 'rank_missing')

        input_peer = self.getInputPeer('address', escrow)
        if (input_peer is None):
            self.createSessionError(session_id, rank, 'escrow_not_found')
            return (False, 'escrow_not_found')

        if (encrypted_output_address is None):
            self.createSessionError(session_id, rank)
            return (False, 'output_missing')

        input_peer['session_id'] = session_id
        self.addOutputAddress(encrypted_output_address)
        input_peer['flagged'] = True
        self._number_peers += 1
        self._unseen_tx_escrow_addresses.append(input_peer['address'])
        return True, None

    def clearReports(self, input_peer_id):
        # Assume that all other mixing peers could NAK the check request, only sending peer is convinced
        self._escrow_addresses[input_peer_id]['report'] = [False] * self._mixnet_size
        self._escrow_addresses[input_peer_id]['report'][self._rank] = True
        return

    def addOutputAddress(self, output_address):
        # ToDo: Check whether valid bitcoin address
        self._encrypted_output_addresses.append(output_address)
        return

    def getEncryptedOutputAddresses(self):
        return self._encrypted_output_addresses

    def getNumberOutputAddresses(self):
        return len(self._encrypted_output_addresses)

    def setPartiallyDecryptedAddresses(self, addresses):
        self._partially_decrypted_addresses = addresses
        self._output_deferred.callback(None)
        return

    def setPartiallyDecryptedAddress(self, i, addr):
        if (self._partially_decrypted_addresses[i] is not None):
            raise RuntimeError('Failed to store shuffle address')
        self._partially_decrypted_addresses[i] = addr
        if (len(filter(lambda x: x is not None, self._partially_decrypted_addresses)) == len(self._assigned_escrows)):
            self._output_deferred.callback(None)

    def getOutputDeferred(self):
        return self._output_deferred

    def getPartiallyDecryptedAddresses(self):
        return self._partially_decrypted_addresses

    def getOutputAddresses(self):
        """ Note: You cannot use this to manipulate stored output addresses """
        return map(lambda a: a['output'], self.getAssignedEscrows())

    def assignOutputAddresses(self, addresses):
        assigned_escrows = self.getAssignedEscrows()
        for i in xrange(0, len(addresses)):
            self._escrow_addresses[assigned_escrows[i]['id']]['output'] = addresses[i]
        return
