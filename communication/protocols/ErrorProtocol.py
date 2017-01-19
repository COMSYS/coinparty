""" CoinParty - Error Protocol
    CAUTION: This is not operable!
    This protocol is SUPPOSED to recover from any protocol errors
    such as malicious attacks. Yet, refunding users is BROKEN and must
    be improved upon.

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

from state.BaseState import mstate
import TransactionProtocol as transaction
from low.CoinPartyProxy import bitcoind, transaction_confirmed
from low.log import Logger
log = Logger('errorrev')


# FIXME: This is inoperable! It may be wiser to have users submit a (fresh) refund address as well.
def returnFunds(txid, escrow_address, target_value):
    """ In case of improper commitment transaction, return funds (partially).
        If the input peer committed too few Bitcoins, refund everything.
        If the input peer committed too many Bitcoins, refund everything that
        was too much.
        Return True if the input peer holding the transaction may still
        participate, False otherwise. """

    def _debug_log(refund_txid):
        log.info('Refund sent via transaction ' + str(refund_txid))
        return

    try:
        tx = bitcoind.getrawtransaction(txid)
    except:
        log.error('Could not find transaction!')
        raise RuntimeError('transaction_not_found')

    # If the transaction is not yet confirmed, don't be fooled
    if (not transaction_confirmed(tx['txid'])):
        log.warning('Will not refund unconfirmed transaction!')
        return True

    for i in xrange(0, len(tx['vout']) + 1):
        if (tx['vout'][i]['scriptPubKey']['addresses'][0] == escrow_address):
            break

    if (i == len(tx['vout'])):
        log.error('Could not find escrow address in transaction...')
        log.error('Transaction was:')
        log.error(str(tx))
        raise RuntimeError('escrow_not_found')

    try:
        transaction_value = float(tx['vout'][i]['value'])
    except:
        log.error('Could not read transaction value. Probably not a CoinParty transaction.')
        raise RuntimeError('transaction_malformed')

    if (transaction_value < target_value):
        refund_value = transaction_value
        still_allowed = False
    elif (transaction_value > target_value):
        refund_value = transaction_value - target_value
        still_allowed = True
    else:
        log.warning('Refund method called altough there is nothing to refund.')
        return True

    # Try to find out an address that is guaranteed to have been under the user's control
    # FIXME: This is probably not possible

    state = mstate.findState(txid)
    input_peer = state.input.getInputPeer('txid', txid)

    refund_tx = transaction.createTransaction(
        txid,
        tx['vout'][i]['scriptPubKey']['addresses'][0],
        refund_value - state.getTransactionFee(),
        input_peer['id'],
        state
    )
    refund_tx.addCallback(transaction.broadcastTransaction)
    refund_tx.addCallback(_debug_log)

    return still_allowed
