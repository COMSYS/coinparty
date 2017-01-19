""" CoinParty - Escrow Address Precomputation
    Precompute escrow addresses that users will send their bitcoins to
    be mixed to. Each user receives an individual escrow address.
    We use SMC-based secure key generation to make all mixpeers
    compute the keypair used to control an escrow address together.

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

import low.Bitcoin as bcc
from low.smpc.base import invert
from state.BaseState import mstate

from low.log import Logger, DeferredLogger
log = Logger('escrow')


def generate_escrows(_, state, amount=3):

    addresses = [None] * (amount)

    def compute_pubkey_address(pubkey_point, using_testnet):
        """ Compute Bitcoin addresses from public keys """
        try:
            pubkey = bcc.serializeEcPoint(pubkey_point, binary=True)
            addr = bcc.computeBitcoinAddress(pubkey, using_testnet)
            return {'pubkey' : pubkey, 'addr' : addr}
        except BaseException as e:
            log.error('Failed computing Bitcoin address.')
            log.error('Error message: ' + str(e))
            raise RuntimeError(str(e))

    def store_address(address, i):
        """ Store computed Bitcoin addresses """
        try:
            addresses[i] = address
            return address
        except BaseException as e:
            log.error('Failed storing Bitcoin address.')
            log.error('Error message: ' + str(e))
            raise RuntimeError(str(e))

    def generate_private_key_share_and_public_key(index):
        """ Generate private key shares """
        try:
            smpc_value = state.smpc.newValue('dkg', state, 'd', index)
            smpc_value.initialize()
            return smpc_value.getPublicValue()
        except BaseException as e:
            log.error('Failed generating private keys.')
            log.error('Error message: ' + str(e))
            raise RuntimeError(str(e))

    def generate_k_and_kG(index):
        """ Pre-compute nonce "k" for ECDSA signature """
        try:
            smpc_value = state.smpc.newValue('dkg', state, 'k', index)
            return smpc_value.initialize()
        except BaseException as e:
            log.error('Failed preparing nonces.')
            log.error('Error message: ' + str(e))
            raise RuntimeError(str(e))

    def compute_k_inv_share(k_deferred, index):
        """ Pre-compute list of k_inv as inverse elements of k """

        def mul_shares(_):  # [u] = [k] * [e]
            e_share = state.smpc.getValue('e', index)
            k_share = state.smpc.getValue('k', index)
            smpc_value = state.smpc.newValue('mul', state, 'us', index)
            return smpc_value.initialize(e_share, k_share)

        def recombine_u(_):  # Recombine [u] ~> u
            u_share = state.smpc.getValue('us', index)
            smpc_value = state.smpc.newValue('rec', state, 'u', index)
            return smpc_value.initialize(u_share)

        def inv_u(_):
            smpc_value = state.smpc.getValue('u', index)
            inverted = smpc_value.getPublicValue()
            inverted.addCallback(invert)
            return inverted

        def mul(u_inv):
            e_share = state.smpc.getValue('e', index)
            k_inv_share = state.smpc.newValue('cmul', state, 'ki', index)
            return k_inv_share.initialize(u_inv, e_share)

        def calc(_):
            smpc_value = state.smpc.newValue('dkg', state, 'e', index)
            k_inv_share = smpc_value.initialize()
            k_inv_share.addCallback(mul_shares)
            k_inv_share.addCallback(recombine_u)
            k_inv_share.addCallback(inv_u)
            k_inv_share.addCallback(mul)
            return k_inv_share

        try:
            k_deferred.addCallback(calc)
            return k_deferred
        except BaseException as e:
            log.error('Failed generating inverted nonces.')
            log.error('Error message: ' + str(e))
            raise RuntimeError(str(e))

    def compute_k_inv_d_share(k_inv_deferred, d_deferred, index):
        """ Compute the share of k^-1 * d """
        def calc(list):
            k_inv_share = state.smpc.getValue('ki', index)
            d_share = state.smpc.getValue('d', index)
            k_inv_d_share = state.smpc.newValue('mul', state, 'kid', index)
            return k_inv_d_share.initialize(k_inv_share, d_share)
        try:
            sync = DeferredList([k_inv_deferred, d_deferred])
            sync.addCallback(calc)
            return sync
        except BaseException as e:
            log.error('Failed multiplying inverted nonces with generator.')
            log.error('Error message: ' + str(e))
            raise RuntimeError(str(e))

    def fire_deferred(_, deferred):
        deferred.callback(None)
        return

    def store_escrow(_, index):
        public_key = addresses[index]['pubkey']
        bitcoin_address = addresses[index]['addr']
        state.input.storeGeneratedEscrow(index, public_key, bitcoin_address)
        return

    def create_escrow(_, i):
        d = generate_private_key_share_and_public_key(i)
        d.addCallback(compute_pubkey_address, using_testnet=mstate.usingTestnet())
        d.addCallback(store_address, i=i)
        d.addErrback(DeferredLogger.error, msg='Could not run callback chain')

        k = generate_k_and_kG(i)
        k.addErrback(DeferredLogger.error, msg='Could not run k callback chain')

        k_inv = compute_k_inv_share(k, i)
        k_inv_d = compute_k_inv_d_share(k_inv, d, i)
        k_inv.addErrback(DeferredLogger.error, msg='Could not run k_inv callback chain')

        sync_point = DeferredList([d, k, k_inv, k_inv_d])
        sync_point.addCallback(store_escrow, index=i)
        return sync_point

    """ Debug helpers """

    def _debug_print_d(private_key, i):
        log.debug('Private key ' + str(i) + ': ' + str(hex(int(private_key)))[2:])

    def _debug_reconstruct_d(_, i):
        d_share = state.smpc.getValue('d', i)
        smpc_value = state.smpc.newValue('rec', state, 'debug_d', i)
        private_key = smpc_value.getPublicValue()
        smpc_value.initialize(d_share)
        private_key.addCallback(_debug_print_d, i=i)
        return private_key

    def _debug_print_k(k, i):
        log.debug('k     ' + str(i) + ': ' + str(int(k)))

    def _debug_reconstruct_k(_, i):
        k_share = state.smpc.getValue('k', i)
        smpc_value = state.smpc.newValue('rec', state, 'debug_k', i)
        smpc_value.initialize(k_share)
        k = smpc_value.getPublicValue()
        k.addCallback(_debug_print_k, i=i)
        return k

    def _debug_print_k_inv(k_inv, i):
        log.debug('k_inv ' + str(i) + ': ' + str(int(k_inv)))

    def _debug_reconstruct_k_inv(_, i):
        k_inv_share = state.smpc.getValue('ki', i)
        smpc_value = state.smpc.newValue('rec', state, 'debug_k_inv', i)
        smpc_value.initialize(k_inv_share)
        k_inv = smpc_value.getPublicValue()
        k_inv.addCallback(_debug_print_k_inv, i=i)
        return k_inv

    def _debug_print_k_inv_d(k_inv_d, i):
        log.debug('k_inv_d ' + str(i) + ': ' + str(int(k_inv_d)))

    def _debug_reconstruct_k_inv_d(_, i):
        k_inv_d_share = state.smpc.getValue('kid', i)
        smpc_value = state.smpc.newValue('rec', state, 'debug_k_inv_d', i)
        smpc_value.initialize(k_inv_d_share)
        k_inv_d = smpc_value.getPublicValue()
        k_inv_d.addCallback(_debug_print_k_inv_d, i=i)
        return k_inv_d

    def _debug_print_e(e, i):
        log.debug('e     ' + str(i) + ': ' + str(int(e)))

    def _debug_reconstruct_e(_, i):
        e_share = state.smpc.getValue('e', i)
        smpc_value = state.smpc.newValue('rec', state, 'debug_e', i)
        smpc_value.initialize(e_share)
        e = smpc_value.getPublicValue()
        e.addCallback(_debug_print_e, i=i)
        return e

    def _debug_print_address(addr, i):
        log.debug('Address ' + str(i) + ': ' + addr['addr'])
        return addr

    log.info('Entered escrow address generation.')
    log.info('Generating ' + str(amount) + ' escrow addresses.')

    deferreds = []
    for i in xrange(0, (amount + 1)):
        deferreds.append(Deferred())
    for i in range(amount):
        deferreds[i].addCallback(create_escrow, i=i)
        deferreds[i].addCallback(fire_deferred, deferred=deferreds[i + 1])

    last_deferred = deferreds[-1]
    last_deferred.addCallback(DeferredLogger.info, msg='Escrow address generation concluded.')
    last_deferred.addErrback(DeferredLogger.error, msg='Escrow address FAILED.')
    deferreds[0].callback(None)
    return last_deferred
