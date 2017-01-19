""" CoinParty - P2P Endpoint
    This file constitutes the communication endpoint for our custom
    P2P protocol used between peers to negotiate state and carry out
    secure multiparty computation.

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

from Crypto.Random import random
import hashlib

from protocols.low.MsgReceiver import MsgReceiver
from protocols.low.Transaction import ConsistentBroadcastTransaction, BroadcastTransaction


from twisted.internet import protocol, reactor, ssl
from twisted.internet.defer import Deferred, DeferredList, maybeDeferred
from twisted.internet.task import deferLater

import protocols.low.Requests as req
from protocols.low.log import Logger, DeferredLogger
log = Logger('p2p')


def createP2pServer(state, port, cert=None):
    server = P2pServer(state, port, cert)
    deferred = server.start()
    return (server, deferred)


def createP2pClient(state, ssl=False):
    client = P2pClient(state, ssl)
    deferred = client.start()
    return (client, deferred)


class P2pServer(object):

    def __init__(self, state, port, cert):
        self.server = None
        self.port = port
        self.state = state
        self.cert = cert
        self.all_connected_deferred = None

    def start(self):
        def _debug_working(_):
            log.debug('P2P server is up and ready.')
        self.all_connected_deferred = Deferred()
        factory = self.P2pServerProtocolFactory(self.state, self.P2pServerProtocol, self.all_connected_deferred)
        if (self.cert is None):
            self.server = reactor.listenTCP(self.port, factory)
        else:
            with open(self.cert, 'r') as f:
                cert_data = f.read()
            certificate = ssl.PrivateCertificate.loadPEM(cert_data)
            reactor.listenSSL(self.port, factory, certificate.options())
        self.all_connected_deferred.addCallback(_debug_working)
        return self.all_connected_deferred

    def shutdown(self):
        d = maybeDeferred(self.server.stopListening)
        d.addCallback(DeferredLogger.debug, msg='P2P server was shut down.')
        return d

    class P2pServerProtocol(MsgReceiver):

        def __init__(self, state):
            # Link to shared state of all protocols
            self.state = state
            # Local state for one specific communication partner
            self.address_provided = False
            MsgReceiver.__init__(self)

        def getBroadcastTransaction(self, msg):
            """ If any broadcast message is received, try to match it again
                an already established state. """

            # Look up the msg's sequence number for a pending transaction
            transaction = self.state.transactions.findTransaction(msg['seq'])

            # If no transaction is found, establish a state and start replying
            if (transaction is None):
                if (msg['msg'] == 'cbrc'):
                    """ Ignore prematurely received final-messages.
                        If final is received without first receiving send, the msg
                        is unknown and also the sender is malicious. """
                    if (not msg['type'] == 's'):
                        return None
                    msg_type = req.MessageHandler.getMessageType(msg['m'])
                    request_handler = req.getMessageHandler(msg_type)
                    transaction = ConsistentBroadcastTransaction(
                        self.state.mixnet.getRank(),
                        self.state.crypto.getCrypter(),
                        self.state.mixnet.getConnectedMixpeers(),
                        self.state.mixnet.getMixnetSize(),
                        self.state.mixnet.getMixpeerThreshold(),
                        msg['seq'],
                        None,
                        self.state.getP2pClientDeferred()
                    )
                elif (msg['msg'] == 'rbrc'):
                    raise RuntimeError('Reliable broadcast is not implemented yet.')
                else:
                    raise RuntimeError('Unknwon broadcast type')
                self.state.transactions.addTransaction(transaction)
                if (msg_type in req.MessageTypes.smpc_msgs):
                    smpc_msg = request_handler.decode(msg['m'])
                    smpc_value = self.state.smpc.getValue(smpc_msg['id'], smpc_msg['index'])
                    if (smpc_value is None):
                        smpc_value = self.state.smpc.newValue(
                            smpc_msg['alg'],
                            self.state,
                            smpc_msg['id'],
                            smpc_msg['index']
                        )
                    transaction.defineCallback(request_handler, smpc_value)
                else:
                    transaction.defineCallback(request_handler, self.state)
            return transaction

        def msgReceived(self, msg_bin):
            """ Handle messages received by P2P protocol """
            rank = req.MessageHandler.getRank(msg_bin)
            crypter = self.state.mixnet.getMixpeer(rank)['crypt'] if rank is not None else None
            if (not req.MessageHandler.checkSignature(msg_bin, crypter)):
                log.error('Signature check failed.')
            msg_type = req.MessageHandler.getMessageType(msg_bin)
            request_handler = req.getMessageHandler(msg_type)

            # If msg type is unknown, ignore message
            if (request_handler is None):
                return

            msg = request_handler.decode(msg_bin)

            if (msg_type in req.MessageTypes.brdc_msgs):
                transaction = self.getBroadcastTransaction(msg)
                result = request_handler.processRequest(msg, transaction, self.state)
            elif (msg_type in req.MessageTypes.smpc_msgs):
                smpc_value = self.state.smpc.getValue(msg['id'], msg['index'])
                if (smpc_value is None):
                    smpc_value = self.state.smpc.newValue(
                        msg['alg'],
                        self.state,
                        msg['id'],
                        msg['index']
                    )
                result = request_handler.processRequest(msg, smpc_value)
            else:
                result = request_handler.processRequest(msg, self.state)
            if (result is not None):
                response = result
                self.respond(response)
            return


    class P2pServerProtocolFactory(protocol.Factory):
        """ Create new instances for handlers of the P2P server protocol. """
        def __init__(self, state, protocol, all_connected_deferred):
            self.state = state
            self.protocol = protocol
            self.counter = 0
            self.all_connected_deferred = all_connected_deferred
            self.allow_connections = True

        def buildProtocol(self, addr):
            if (not self.allow_connections):
                return None
            log.debug('Client connected!')
            protocol = self.protocol(self.state)
            self.counter += 1
            if (self.counter == self.state.mixnet.getMixnetSize() - 1):
                self.allow_connections = False
                self.all_connected_deferred.callback(None)
            return protocol


class P2pClient(object):

    def __init__(self, state, ssl):
        self.state = state
        self.state._p2p_client = self
        self._peers = []
        self.using_ssl = ssl
        self.shutdown_deferreds = None

    def start(self):
        def _debug_working(_):
            log.debug('P2P client is up and ready.')
        connect_deferred = Deferred()
        connect_deferred.addCallback(_debug_working)
        # Connect to other mixing peers
        shutdown_deferreds = []
        for peer in self.state.mixnet.getOtherMixpeers():
            shutdown_deferred = Deferred()
            shutdown_deferreds.append(shutdown_deferred)
            if (self.using_ssl):
                connection = connection = reactor.connectSSL(
                    peer['host'],
                    peer['port'],
                    P2pClient.P2pClientFactory(self.state, peer['rank'], connect_deferred, shutdown_deferred),
                    ssl.ClientContextFactory()
                )
            else:
                connection = reactor.connectTCP(
                    peer['host'],
                    peer['port'],
                    P2pClient.P2pClientFactory(self.state, peer['rank'], connect_deferred, shutdown_deferred)
                )
            self._peers.append(connection)
        self.shutdown_deferreds = DeferredList(shutdown_deferreds)
        return connect_deferred

    def shutdown(self):
        for peer in self._peers:
            log.debug('Initiated client-side disconnect from peer ' + str(self._peers.index(peer)) + '.')
            peer.disconnect()

        self.shutdown_deferreds.addCallback(DeferredLogger.debug, msg='P2P client was shut down.')
        return self.shutdown_deferreds

    class P2pClientProtocol(MsgReceiver):

        def __init__(self, peer_rank, state):
            self.peer_rank = peer_rank
            self.state = state
            MsgReceiver.__init__(self)

        def connectionLost(self, *a):
            log.debug('Connection to peer ' + str(self.peer_rank) + ' is being shut down.')
            self.factory.shutdown_deferred.addCallback(DeferredLogger.debug, msg='Connection shutdown complete.')
            try:
                self.state.mixnet.lostConnection(self.peer_rank)
            except BaseException as e:
                log.critical('Got error: ' + str(e) + '. Shutting down mixnet entirely.')
                self.factory.shutdown_deferred.callback(self)
                self.state.triggerErrorDeferred(e)
                return
            self.factory.shutdown_deferred.callback(self)

        def connectionMade(self):
            log.info('Connected to mixing peer with rank ' + str(self.peer_rank) + ' @ ' + self.state.mixnet.getMixpeerAddress(self.peer_rank))
            self.state.mixnet.establishedConnection(self.peer_rank, self)
            if (self.state.mixnet.allConnectionsEstablished()):
                self.factory.all_connected_deferred.callback(None)

        def request(self, packet):
            self.transport.write(packet)
            return

        def request_new_addresses(self, number_addresses):
            self.transport.write('{\"rank\":' + str(self.state.mixnet.getRank()) + ',\"value\":' + str(number_addresses) + '}')
            return

        def msgReceived(self, msg_bin):
            rank = req.MessageHandler.getRank(msg_bin)
            crypter = self.state.mixnet.getMixpeer(rank)['crypt'] if rank is not None else None
            if (not req.MessageHandler.checkSignature(msg_bin, crypter)):
                log.error('Signature check failed.')
            msg_type = req.MessageHandler.getMessageType(msg_bin)
            request_handler = req.getMessageHandler(msg_type)

            # Ignore msg if msg type is unknown
            if (request_handler is None):
                print('Request Handler is none')
                return

            msg = request_handler.decode(msg_bin)
            self.state.transactions.receivedMessage(msg)  # This implicitly fires deferreds once everything is received
            return

    class P2pClientFactory(protocol.ClientFactory):

        def __init__(self, state, rank, all_connected_deferred, shutdown_deferred):
            self.peer_rank = rank
            self.maxDelay = 5
            self.state = state
            self.all_connected_deferred = all_connected_deferred
            self.shutdown_deferred = shutdown_deferred

        def startedConnecting(self, connector):
            log.info('Attempting to connect to peer ' + str(self.peer_rank) + '.')
            return

        def clientConnectionLost(self, conenctor, reason):
            pass

        def clientConnectionFailed(self, connector, reason):
            deferLater(reactor, 2, connector.connect)

        def buildProtocol(self, addr):
            """ Create a new client instantiation as the connection has been established. """
            self.addr = addr
            p2p_client_protocol = P2pClient.P2pClientProtocol(self.peer_rank, self.state)
            p2p_client_protocol.factory = self

            return p2p_client_protocol

    def isAcked(self, params):
        try:
            ack = True if (params['ack'] == 'true') else False
        except KeyError:
            ack = False
        return ack

    def request_new_addresses(self, _, number_addresses=5):
        # FIXME: This is inoperable.
        log.warning('Adding new addresses not yet implemented. But I WOULD add ' + str(number_addresses) + ' addresses.')
        other_peers = self.state.mixnet.getOtherMixpeers()

        d = Deferred()
        self.state.test_deferred = d

        d.addCallback(self._generate_new_addresses, number_addresses=number_addresses)
        for peer in other_peers:
            peer['instance'].request_new_addresses(number_addresses)

        return d

    def _generate_new_addresses(self, number_addresses):
        # FIXME: Must set encrypted output address somehow before input peer is returned
        log.warning('I should create ' + str(number_addresses) + ' new addresses.')

    def _obtain_address(self):
        d = Deferred()
        return d

    def response_helo(self, response, value, is_positive, opt):
        log.debug('Entered helo result fetcher')
        result = dict()
        input_peer = opt
        try:
            rank = int(response['rank'])
        except KeyError:
            self.state.input.createSessionError(input_peer['session_id'], None, 'rank_missing')
        acked = self.isAcked(response)
        result['value'] = input_peer
        result['is_positive'] = acked
        input_peer['report'][rank] = acked
        return result

    def request_helo_callback(self, input_peer, encrypted_output_address):

        # Create session ID
        session_id_string = str(random.getrandbits(128))
        h = hashlib.sha256()
        h.update(session_id_string)
        session_id = h.hexdigest()
        input_peer['session_id'] = session_id

        # Store output address
        self.state.input.addOutputAddress(encrypted_output_address)

        self.state.input.clearReports(input_peer['id'])

        seq = self.state.transactions.getNextSequenceNumber()
        msg = req.helo.encode(self.state.mixnet.getRank(), seq, self.state.crypto.getCrypter(), input_peer, encrypted_output_address)
        peers = self.state.mixnet.getConnectedMixpeers()
        # Create deferred for broadcast, fired after the last response is received
        broadcast_deferred = self.state.transactions.addTransaction(
            BroadcastTransaction(self.state.mixnet.getRank(), peers, msg, seq, self.response_helo, input_peer)
        )
        broadcast_deferred.addCallback(self.state.commit.checkInputPeerThreshold)
        return broadcast_deferred

    def request_helo(self, encrypted_output_address):
        address_deferred = Deferred()

        address_deferred.addErrback(self.request_new_addresses)
        address_deferred.addCallback(self.request_helo_callback, encrypted_output_address=encrypted_output_address)

        # Assign new address
        input_peer = self.state.input.addInputPeer()
        self.state.commit.increasePeerCount()
        if (input_peer is not None):
            log.debug('I\'m going to request new addresses...')
            address_deferred.errback(5)
        else:
            log.debug('Immediately going to real callback.')
            address_deferred.callback(input_peer)
        return address_deferred
