""" CoinParty - Mixnet State
    Holds overall mixnet parameters such as size or the individual peers.

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

from math import floor
import pyelliptic

from ..low.log import Logger
log = Logger('mixnet_state')


class MixnetState():
    def __init__(self, mixnet_id, mixnet_size, rank):
        # Mixnet base information
        self._mixnet_id = mixnet_id
        self._mixnet_size = mixnet_size
        self._mixing_peers = [None] * self._mixnet_size
        self._rank = rank
        self._secret_threshold = int(floor(mixnet_size / 3.0))

        # Mixnet connection information
        self._number_connected_peers = 0

    #
    # Mixnet metadata
    #

    def getMixnetID(self):
        return self._mixnet_id

    def getMixnetSize(self):
        return self._mixnet_size

    def getMixpeerThreshold(self):
        return self._secret_threshold

    #
    # Mixpeer metadata
    #

    def addMixpeer(self, id, rank, p2p_host, p2p_port, web_addr, public_key):
        """ Add a mixing peer to a mixnet's protocol state.

            Expected parameters:
            - id            The peer's ID
            - rank          The peer's rank within the particular mixnet
            - p2p_host      Hostname of the peer's P2P server
            - p2p_port      Port used by the peer's P2P server
            - web_addr      Address of the peer's web interface, without "https://"
            - public_key    Hexadecimal presentation of the peer's EC public key
        """
        crypt = pyelliptic.ECC(curve='secp256k1', pubkey=public_key.decode('hex'))
        peer = {
            'id'       : id,
            'rank'     : rank,
            'web'      : 'http://' + web_addr,  # FIXME: Use https when TLS is in place!
            'host'     : p2p_host,
            'port'     : p2p_port,
            'pub'      : public_key,
            'crypt'    : crypt,
            'instance' : None
        }
        self._mixing_peers[rank] = peer

    def getMixpeer(self, rank):
        return self._mixing_peers[rank]

    def getMixpeerAddress(self, rank):
        return self._mixing_peers[rank]['host'] + ':' + str(self._mixing_peers[rank]['port'])

    def getMixpeers(self):
        return self._mixing_peers

    def getOtherMixpeers(self):
        return self._mixing_peers[:self.getRank()] + self._mixing_peers[self.getRank() + 1:]

    def getConnectedMixpeers(self):
        # FIXME: This does not handle disconnected peers.
        return self.getOtherMixpeers()

    def getRank(self):
        return self._rank

    def isLastMixpeer(self, rank=None):
        rank = self.rank if rank is None else rank
        return True if (rank == self.getMixnetSize() - 1) else False

    #
    # Mixnet connection management
    #

    def lostConnection(self, rank):
        peer = self.getMixpeer(rank)
        if (peer['instance'] is not None):
            self._number_connected_peers -= 1
            peer['instance'] = None
            # TODO: Shutdown if insufficient peers remain connected

    def establishedConnection(self, rank, protocol_instance):
        if (self.getMixpeer(rank)['instance'] is None):
            self._number_connected_peers += 1
            self._mixing_peers[rank]['instance'] = protocol_instance

    def allConnectionsEstablished(self):
        return (self._number_connected_peers == self._mixnet_size - 1)  # Minus one since peer is not connected to itself
