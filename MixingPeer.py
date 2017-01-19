#!/usr/bin/env python

""" CoinParty - Mixing Peer
    Main executable

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

from communication.P2pEndpoints import \
    createP2pServer, createP2pClient
from communication.WebServer import createWebServer

import communication.protocols.InitializationProtocol as init
import communication.protocols.EscrowAddresses as escrow
import communication.protocols.CommitmentProtocol as commit
import communication.protocols.ShufflingProtocol as shuffle
import communication.protocols.TransactionProtocol as transaction

from communication.protocols.state.BaseState import mstate, BaseState

from twisted.internet import reactor
from twisted.internet.defer import DeferredList
from twisted.python.failure import Failure
from configobj import ConfigObj
from os.path import isfile

import sys
import argparse

from communication.protocols.low.log import Logger, DeferredLogger
log = Logger('main')

pickle = None
unpickle = None


class MixingPeer():
    """ This class models the behavior of one mixing peer in a
        CoinParty mixnet. """

    def startWebServer(self, port):
        (webserver, webserver_deferred) = createWebServer(port)
        mstate.setWebServer(webserver)
        return webserver_deferred

    def startP2pInfrastructure(self, state, port):
        (p2pserver, p2pserver_deferred) = createP2pServer(state, port)
        (p2pclient, p2pclient_deferred) = createP2pClient(state)
        deferred_list = [p2pserver_deferred, p2pclient_deferred]
        state.setP2pServer(p2pserver, p2pserver_deferred)
        state.setP2pClient(p2pclient, p2pclient_deferred)
        return DeferredList(deferred_list)

    def localShutdown(self, _, mixnet_id):
        def _serverShutdown(_):
            return state.getP2pServer().shutdown()

        def _removeState(_, state):
            mstate.removeState(state)
            if (len(mstate.getStates()) == 0):
                self.realShutdown()
        state = mstate.getState(mixnet_id)
        state.setShutdownFlag()
        cd = state.getP2pClient().shutdown()
        cd.addCallback(_serverShutdown)
        cd.addCallback(_removeState, state=state)

    def globalShutdown(self, failure=None):
        if (isinstance(failure, Failure)):
            log.error('Shutting down due to error: {}'.format(
                str(failure.getErrorMessage())
            ))
            log.debug('Traceback:\n{}'.format(
                str(failure.getTraceback())
            ))
        elif (isinstance(failure, BaseException)):
            log.error('Shutting down due to error: {}'.format(str(failure)))
        for state in mstate.getStates():
            self.localShutdown(None, state.mixnet.getMixnetID())

    def realShutdown(self):
        def _finishShutdown(_):
            reactor.stop()
            log.info('Mixing peer has been shut down. Bye.')
        d = mstate.getWebServer().shutdown()
        d.addCallback(_finishShutdown)

    def cancelOperation(self, operation_deferred):
        operation_deferred.cancel()

    def __init__(self, id, mixnet_config):
        """ Create a new mixing peer.

        Assumptions:
        The mixnet is static and known beforehand.
        Once the mixing peer is knows its (predefined) rank it can completely
        take the role of the respective mixing peer. As a consequence the
        building of the mixing P2P network and the assignment of ranks among
        the peers is not implemented.

        Arguments:
        - mixing_peer_id
        - mixnet_config    configuration file for the mixnet
        """

        log.info('Initializing mixing peer {} from config file {}'.format(
            id, mixnet_config
        ))

        if (not isfile(mixnet_config)):
            raise IOError('Mixing peer config file not found: \"{}\"'.format(
                mixnet_config
            ))

        config = ConfigObj(mixnet_config)
        mstate.setGlobalConfig(config['global_config'])

        try:
            me = config['mixing_peers'][id]
        except KeyError:
            log.error('Could not find configuration. Shutting down.')
            sys.exit(1)

        mstate.setMixpeerID(id)

        # Load all necessary addresses
        try:
            web_port = int(me['web_addr'].split(':')[1])
        except KeyError:
            log.error('Could not find web_addr. Shutting down.')
            sys.exit(1)

        webserver_deferred = self.startWebServer(web_port)

        mixnets = config['mixing_networks']
        for mixnet_id in (mixnet_id for mixnet_id in mixnets if id in mixnets[mixnet_id].keys()):
            mixnet = mixnets[mixnet_id]
            me_in_mixnet = mixnet[id]
            try:
                rank = int(me_in_mixnet['rank'])
            except KeyError:
                log.error('Could not find my rank in some mixnet. Shutting down.')
                sys.exit(1)
            try:
                p2p_server_port = int(me_in_mixnet['p2p_addr'].split(':')[1])
            except KeyError:
                log.error('Could not find my p2p address in some mixnet. Shutting down.')
                sys.exit(1)

            state = BaseState(rank, mixnet_id, len(mixnet))
            mstate.appendState(state)

            # Read EC keys and create encryption "endpoint"
            try:
                state.crypto.setCryptoParams(me['prvkey'], me['pubkey'])
            except:
                log.error('Could not read my cryptography parameters. Shutting down.')
                sys.exit(1)

            # Fill available mixing peers (also with own information)
            for peer in mixnet:
                try:
                    rank = int(mixnet[peer]['rank'])
                except KeyError:
                    log.error('Could not find peer rank. Shutting down.')
                    sys.exit(1)
                try:
                    p2p_addr = mixnet[peer]['p2p_addr'].split(':')
                except KeyError:
                    log.error('Could not find peer p2p_addr. Shutting down.')
                    sys.exit(1)
                p2p_host = p2p_addr[0]
                p2p_port = int(p2p_addr[1])
                try:
                    web_addr = config['mixing_peers'][peer]['web_addr']
                except:
                    log.error('Cannot determine web address of mixing peer \'{}\'. Shutting down.'.format(
                        peer
                    ))
                    sys.exit(1)
                try:
                    pubkey = config['mixing_peers'][peer]['pubkey']
                except:
                    log.error('Cannot determine EC public key of mixing peer  \'{}\'. Shutting down.'.format(
                        peer
                    ))
                    sys.exit(1)
                state.mixnet.addMixpeer(
                    peer,
                    rank,
                    p2p_host,
                    p2p_port,
                    web_addr,
                    pubkey
                )

            """ Wait for web server and p2p module being operable,
                then start the operations """
            p2p_deferred = self.startP2pInfrastructure(state, p2p_server_port)
            mixnet_deferreds = DeferredList([webserver_deferred, p2p_deferred])
            mixnet_deferreds.addCallback(
                DeferredLogger.debug, msg='Trying to start initialization.'
            )
            mixnet_deferreds.addCallback(init.initialize, state=state)
            mixnet_deferreds.addCallback(
                DeferredLogger.debug, msg='Trying to start escrow generation.'
            )
            mixnet_deferreds.addCallback(escrow.generate_escrows, state=state)
            mixnet_deferreds.addCallback(
                DeferredLogger.debug, msg='Trying to start commitment phase.'
            )
            mixnet_deferreds.addCallback(commit.commitment_phase, state=state)
            mixnet_deferreds.addCallback(
                DeferredLogger.debug, msg='Trying to start shuffling phase.'
            )
            mixnet_deferreds.addCallback(shuffle.shuffling_phase, state=state)
            mixnet_deferreds.addCallback(
                DeferredLogger.debug, msg='Trying to start transaction phase.'
            )
            mixnet_deferreds.addCallback(
                transaction.transaction_phase, state=state
            )
            mixnet_deferreds.addCallback(
                DeferredLogger.critical, msg='Not implemented past this point!'
            )

            """ Add graceful shutdown as a errback """
            mixnet_deferreds.addErrback(self.globalShutdown)

            """ TODO: At this point, the state SHOULD be renewed (and the old
                one should be archived for other peers to review their
                operation) to allow for a subsequent new mixing without
                re-establishing the connection between peers. """

            error_deferred = state.getErrorDeferred()
            error_deferred.addBoth(
                self.cancelOperation,
                operation_deferred=mixnet_deferreds
            )

        log.info('Initialized mixing peer.')
        log.info('Running event listener now. Bye!')
        reactor.run()


if (__name__ == '__main__'):
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        'id', type=str, help='Rank to assign the mixing peer'
    )
    arg_parser.add_argument(
        '-c', '--config', default='mixnets.conf',
        help='Mixnet configuration file to use'
    )
    args = arg_parser.parse_args()

    MixingPeer(args.id, args.config)
