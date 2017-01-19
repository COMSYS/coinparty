""" CoinParty - Transaction Protocol
    This file contains functionality related to the distributed creation of
    Bitcoin transactions and their broadcasting to the Bitcoin network.

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

from binascii import hexlify

from low.CoinPartyProxy import bitcoind
from low.TransactionStrategies import splitMixingAmount, defineStreamingSchedule
from low.smpc.WrapperSmpcValue import WrapperSmpcValue
from low.smpc.AdditionSmpcValue import AdditionSmpcValue
from low.smpc.ConstantMultiplicationSmpcValue import ConstantMultiplicationSmpcValue

from twisted.internet import reactor
from twisted.internet.defer import Deferred, DeferredList

from hashlib import sha256
import bitcoin as bc
from bitcoin.core.key import CPubKey
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core.scripteval import VerifyScript
import ecdsa.der as der
from Crypto.Random.Fortuna.FortunaGenerator import AESGenerator as SeedablePrngGenerator
from Crypto.Random.random import StrongRandom


from low.log import Logger
log = Logger('transaction_phase')

# ToDo: Temporary construct!
transaction_ctr = 0


def broadcastTransaction(tx):
    return bitcoind.sendrawtransaction(tx)


def createTransaction(txid, vout, value, output_address, escrow_index, state):
    """ Create an transaction from an escrow address, defined by a previous txid, to the output address """

    # This will be the return value, a little indirection to not return a Share.
    tx_deferred = Deferred()

    def _fire_response(tx):
        tx_deferred.callback(tx)
        return

    def _signatureCallback(signature, shares, hash, transaction):
        return signature

    def _computeSignatureShare(hash):

        def _get_R(R_deferred):
            R = R_deferred.x()
            return R

        def _compute_summand2(R, k_inv_d_share):
            summand2 = ConstantMultiplicationSmpcValue(state)
            summand2_deferred = summand2.initialize(R, k_inv_d_share)
            return summand2_deferred

        def _final_sum(deferreds):
            global transaction_ctr
            summand1 = WrapperSmpcValue(state)
            summand2 = WrapperSmpcValue(state)
            summand1.initialize(deferreds[0][1])
            summand2.initialize(deferreds[1][1])
            s = AdditionSmpcValue(state)  # add secret values of summand1, summand2 (see below)
            s_deferred = s.initialize(summand1, summand2)
            return s_deferred

        # Set parameters for creating the share of the signature
        e = int(hexlify(hash), 16)
        kG_deferred = state.smpc.getValue('k', escrow_index).getPublicValue()
        R = state.smpc.getValue('k', escrow_index).getPublicValue()
        k_inv_share = state.smpc.getValue('ki', escrow_index)
        k_inv_d_share = state.smpc.getValue('kid', escrow_index)

        """ Calculation to be performed: S_share = e * k_inv_share + R * k_inv_d_share """
        try:
            summand1 = ConstantMultiplicationSmpcValue(state)
            summand1_deferred = summand1.initialize(e, k_inv_share)
            kG_deferred.addCallback(_get_R)
            kG_deferred.addCallback(_compute_summand2, k_inv_d_share=k_inv_d_share)
            R.addCallback(_get_R)
            S_share = DeferredList([summand1_deferred, kG_deferred])
            S_share.addCallback(_final_sum)
            return (S_share, R)
        except BaseException as ex:
            log.critical('Error in signature generation! Error: ' + str(ex))
            raise RuntimeError('signing_share_failed')

    def _signatureToDER(S, R):
        S_der = der.encode_integer(int(S))
        R_der = der.encode_integer(int(R))

        signature_der = der.encode_sequence(R_der, S_der) + chr(0x01)
        return signature_der

    def _reconstruct_signature(S_share):
        try:
            global transaction_ctr
            final_sum = WrapperSmpcValue(state)
            final_sum.initialize(S_share)
            S = state.smpc.newValue('rec', state, 'S', transaction_ctr)
            return S.initialize(final_sum)
        except BaseException as e:
            log.critical('S reconstruction failed! ' + str(e))
            raise RuntimeError('signing_reconstruct_failed')

    def _computeSignature(S_share_R):
        S_share = S_share_R[0][1]
        R = S_share_R[1][1]

        def _extract_signature(_):
            global transaction_ctr
            signature = state.smpc.getValue('S', transaction_ctr).getPublicValue()
            transaction_ctr += 1
            return signature

        signature = _reconstruct_signature(S_share)
        signature.addCallback(_extract_signature)
        signature.addCallback(_signatureToDER, R=R)
        return signature

    def _computeTransaction(signature, tx, script_pubkey, pubkey):
        txin = tx.vin[0]
        txin.scriptSig = bc.core.script.CScript([signature, pubkey])

        try:
            VerifyScript(txin.scriptSig, script_pubkey, tx, 0, (bc.core.scripteval.SCRIPT_VERIFY_P2SH,))
        except BaseException as e:
            log.error(str(e))
            raise RuntimeError('signing_failed')

        transaction_serialized = bc.core.b2x(tx.serialize())
        return transaction_serialized

    cpub = CPubKey(state.input.getInputPeer('id', escrow_index)['pubkey'])
    txid = bc.core.lx(txid)

    # TXIN information
    txin = bc.core.CMutableTxIn(bc.core.COutPoint(txid, vout))
    txin_scriptPubKey = bc.core.script.CScript([
        bc.core.script.OP_DUP,
        bc.core.script.OP_HASH160,
        bc.core.Hash160(cpub),
        bc.core.script.OP_EQUALVERIFY,
        bc.core.script.OP_CHECKSIG
    ])

    # TXOUT information
    txout = bc.core.CMutableTxOut(
        int(value * bc.core.COIN),
        CBitcoinAddress(output_address).to_scriptPubKey()
    )

    # Create unsigned transaction
    tx = bc.core.CMutableTransaction([txin], [txout])

    # Create signature hash
    sighash = bc.core.script.SignatureHash(txin_scriptPubKey, tx, 0, bc.core.script.SIGHASH_ALL)
    (S_share, R) = _computeSignatureShare(sighash)
    deferreds = DeferredList([S_share, R])
    deferreds.addCallback(_computeSignature)
    deferreds.addCallback(_computeTransaction,
        tx=tx,
        script_pubkey=txin_scriptPubKey,
        pubkey=cpub
    )
    deferreds.addCallback(_fire_response)

    return tx_deferred


def transaction_phase(_, state):

    log.debug('Trying to create transactions from escrows to outputs.')
    state.enterStreamingPhase()
    escrows = state.input.getAssignedEscrows()

    def _debug_done(_):
        log.info('Everything has been transmitted.')
        state.concludeMixing()

    def obtain_splittings_and_schedules(input_peers, split_amount, mixing_window_mins, seed):
        prng_gen = SeedablePrngGenerator()
        prng_gen.reseed(seed)
        prng = StrongRandom(randfunc=prng_gen.pseudo_random_data)
        for input_peer in input_peers:
            input_peer['split'] = splitMixingAmount(split_amount, prng)
            input_peer['schedule'] = defineStreamingSchedule(len(input_peer['split']), mixing_window_mins, prng)
        return

    def serialize_schedules(escrows):
        serialization = []
        for escrow in escrows:
            for i in xrange(0, len(escrow['schedule'])):
                serialization.append((escrows.index(escrow), escrow['schedule'][i]))
        log.debug('Serialization before sorting:\n' + str(serialization))
        serialization.sort(key=lambda x: x[1])
        log.debug('Serialization after sorting:\n' + str(serialization))
        log.debug('Serialization returned:\n' + str([x[0] for x in serialization]))
        return [x[0] for x in serialization]

    def create_transaction(logical_time, escrow, index):

        def _debug_print(tx, escrow, value):
            log.info('    ' + escrow['address'] + ' --> ' + escrow['output'] + ' (' + str(value) + ')')
            return tx

        def _debug_fail(f):
            log.critical('OUTPUT TRANSACTION FAILED! ' + str(f.getErrorMessage()))
            return f

        def _return_next_logical_time(_, logical_time):
            return logical_time

        try:
            timediff = escrow['schedule'][index] - logical_time
        except BaseException as e:
            log.error(str(e))
            return
        d = Deferred()
        d.addCallback(
            createTransaction,
            vout=escrow['tx_vout'],
            value=state.getBitcoinValue(),
            output_address=escrow['output'],
            escrow_index=escrow['id'],
            state=state
        )
        d.addCallback(_debug_print, escrow=escrow, value=escrow['split'][index])
        d.addErrback(_debug_fail)
        d.addBoth(_return_next_logical_time, logical_time=escrow['schedule'][index])
        reactor.callLater(timediff, d.callback, escrow['txid'])
        return d

    log.info('Performing final transactions:')

    # Obtain splittings
    mixing_window = state._mixing_window_mins
    obtain_splittings_and_schedules(escrows, state.getBitcoinValue(), mixing_window, sha256(state.shuffle.getChecksum()).digest())
    transactions = serialize_schedules(escrows)

    finished = Deferred()
    iterators = [enumerate(escrow['schedule']) for escrow in escrows]
    for index in transactions:
        finished.addCallback(
            create_transaction,
            escrow=escrows[index],
            index=(iterators[index].next())[0]
        )
    finished.addCallback(_debug_done)
    finished.callback(0.0)
    return finished
