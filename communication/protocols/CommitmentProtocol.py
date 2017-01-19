""" CoinParty - Commitment Protocol
    This file defines the commitment protocol of CoinParty.
    The mixnet waits for a sufficient number of users to submit their bitcoins
    and data (and a configurable time window to elapse) before starting the
    mixing operation.

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

from low.CoinPartyProxy import bitcoind, transaction_confirmed
from state.BaseState import mstate
import ErrorProtocol as errorrev

from twisted.internet.defer import Deferred, DeferredList

from low.log import Logger, DeferredLogger
log = Logger('commit')


def commitment_phase(_, state):
    """ Implements the protocol flow of the commitment phase of CoinParty. """

    def _obtain_initial_blockhash():
        """ Query bitcoind for the most recent block in the longest chain. """
        hash = bitcoind.getbestblockhash()
        log.info('Initial block hash: ' + str(hash))
        return hash

    def _block_webserver(_):
        """ Disable opportunity of input peer participation. """
        log.debug('Blocking web server for mixnet ' + str(state.mixnet.getMixnetID()))
        state.blockWebServer()
        return None

    def _fire_freezing_deferred(_):
        """ Signal the state that no further input peers will be accepted,
            i.e., the set of assigned escrow addresses will not change anymore. """
        escrows = state.input.getFreezingDeferred()
        escrows.addErrback(DeferredLogger.error, msg='Freezing error: ')
        escrows.callback(None)
        log.debug('Fired freezing deferred.')
        return escrows

    def _wait_for_hash_shares(escrows):
        """ Guarantee that all shares of the checksum hashes are being
            received before the checksum is computed. """
        hash_deferreds = [e['hash_share'] for e in escrows]
        escrow_deferred = Deferred()
        deferred_list = DeferredList([escrow_deferred] + hash_deferreds)
        escrow_deferred.callback(escrows)
        return deferred_list

    def _replace_hash_shares(escrows_and_values):
        """ Just a convenience method to replace all fired hash_share
            deferreds with their actual values. """
        escrows = escrows_and_values[0][1]
        values = filter(lambda x: x[1], escrows_and_values[1:])
        for i in xrange(0, len(values)):
            escrows[i]['hash_share'] = values[i][1]
        return escrows

    def _poll_for_commitments():
        """ Poll the Bitcoin network for transactions that are input peer commitments. """

        def _found_transaction(address, value, txid, vout):
            """ Store a found, yet unconfirmed CoinParty commitment transaction in the state. """
            input_peer = state.input.getInputPeer('address', address)

            if (input_peer is None):
                raise ValueError('escrow_not_found')

            # Remove escrow address from unseen list
            escrow_index = state.input._unseen_tx_escrow_addresses.index(address)
            del state.input._unseen_tx_escrow_addresses[escrow_index]

            # Add txid information to input peer
            log.debug('Found transaction ' + txid)
            log.debug('...assigned to user ' + str(input_peer['id']))
            input_peer['txid'] = txid
            input_peer['tx_vout'] = vout
            state.input._unconfirmed_transactions.append(txid)

            # If the value is wrong, try and repair this
            if (value != state.getBitcoinValue() + state.getTransactionFee()):
                log.warning('Wrong input. Refunding.')
                eligible = errorrev.returnFunds(txid, address, state._bitcoin_value)
                if (not eligible):
                    log.warning('Detected user that commited too few Bitcoins.')
                    raise RuntimeError('wrong_value')
            return

        def _poll_new_transactions(addresses, block_hash):
            """ Poll bitcoind for those addresses that occured since the block
                referred to by the last block hash. """

            def has_next_block(block):
                return True if 'nextblockhash' in block else False

            def filter_transactions(txs):
                """ Directly filter out the information we need """

                def _filter_transaction(tx):
                    result = []
                    for i in xrange(0, len(tx['vout'])):
                        filtered_tx = dict()
                        filtered_tx['txid'] = tx['txid']
                        filtered_tx['addr'] = tx['vout'][i]['scriptPubKey']['addresses'][0]
                        filtered_tx['vout'] = int(tx['vout'][i]['n'])
                        filtered_tx['value'] = tx['vout'][i]['value']
                        filtered_tx['blockhash'] = tx['blockhash']
                        result.append(filtered_tx)
                    return result

                filtered_txs = []
                for tx in txs:
                    if (tx is None):
                        # In the testnet, transactions may apparently be broken
                        if (mstate.usingTestnet()):
                            log.warning('Found invalid transaction in testnet.')
                            continue
                        else:
                            raise RuntimeError('invalid_transaction')

                    # If transaction is not in the format we expect, it's definitely not one we care about
                    try:
                        filtered_tx = _filter_transaction(tx)
                        filtered_txs += filtered_tx
                    except KeyError:
                        continue
                return filtered_txs

            def get_transactions(block):
                txids = block['tx']
                txs = filter_transactions([bitcoind.getrawtransaction(txid) for txid in txids])
                return txs

            new_txs = []
            current_block = bitcoind.getblock(block_hash)
            while (has_next_block(current_block)):
                log.info('Checking block ' + current_block['hash'] + '...')
                transactions = get_transactions(current_block)
                for tx in transactions:
                    if (tx['addr'] in addresses):
                        log.info('Found transaction to "' + tx['addr'] + '"!')
                        log.info('txid: ' + tx['txid'] + '; value: ' + str(tx['value']))
                        new_txs.append(tx)
                current_block = bitcoind.getblock(current_block['nextblockhash'])
            return (new_txs, current_block['hash'])

        def _poll_tx_confirmations(txids, confirmations=6):
            """ Poll the Bitcoin network for confirmations of already seen CoinParty transactions. """
            result = []
            for txid in txids:
                if transaction_confirmed(txid=txid, confirmations=confirmations):
                    result.append(txid)
            return result

        log.debug('Polling...')
        unseen_escrows = state.getUnseenTransactionEscrows()
        if (len(unseen_escrows) > 0):
            log.debug('Looking for transactions to: ' + str(unseen_escrows))
            (new_txs, blockhash) = _poll_new_transactions(unseen_escrows, state.getLastBlockHash())
            state.setLastBlockHash(blockhash)
            for tx in new_txs:
                _found_transaction(
                    tx['addr'],
                    tx['value'],
                    tx['txid'],
                    tx['vout']
                )
            if (state.input.inputPeersFrozen() and len(state.getUnseenTransactionEscrows()) == 0):
                log.debug('Found all transactions. From now on, I just wait for their confirmation.')

        new_confirmed_txids = _poll_tx_confirmations(state.getUnconfirmedTransactions())
        for txid in new_confirmed_txids:
            state.foundCommitment(txid)

        if (state.allPaymentsReceived()):
            log.info('All input peers commited their coins!')
            state.commit.firePollingDeferred()
        return

    """ Begin of the actual commitment phase definition. """

    state.setLastBlockHash(_obtain_initial_blockhash())
    state.commit.startPeerGathering()

    threshold_deferred = state.commit.getThresholdDeferred()
    threshold_deferred.addCallback(_block_webserver)
    threshold_deferred.addCallback(_fire_freezing_deferred)
    threshold_deferred.addCallback(_wait_for_hash_shares)
    threshold_deferred.addCallback(_replace_hash_shares)
    threshold_deferred.addErrback(DeferredLogger.error, msg='Error in threshold deferred: ')

    polling_deferred = state.commit.setPollingDeferred(
        _poll_for_commitments,
        10
    )
    polling_deferred.addErrback(DeferredLogger.error, 'Error in polling deferred: ')

    log.info('Unblocking web server.')
    state.unblockWebServer()

    """ Commitment phase is concluded once the desired number of input peers is reached AND
        each of the input peers has commited their bitcoins. """
    return DeferredList([threshold_deferred, polling_deferred])
