""" CoinParty - Bitcoin Proxy
    Define a specialized bitcoind proxy that serves the needs of CoinParty.
    Based on python-bitcoinlib.

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

from bitcoin.rpc import Proxy as BitcoinlibProxy, JSONRPCError
from bitcoin.core import x
from bitcoin import SelectParams
from ..state.BaseState import mstate
from log import Logger
log = Logger('proxy')

HTTP_TIMEOUT = 30


class Proxy(BitcoinlibProxy):
    """ Extend the BitcoinlibProxy by calls that CoinParty requires to perform during the Commitment /transaction phases. """
    def __init__(self, service_url=None,
                 service_port=None,
                 btc_conf_file=None,
                 timeout=HTTP_TIMEOUT,
                 **kwargs):
        super(BitcoinlibProxy, self).__init__(service_url=service_url,
                                              service_port=service_port,
                                              btc_conf_file=btc_conf_file,
                                              timeout=HTTP_TIMEOUT,
                                              **kwargs)
        try:
            info = self.getinfo()
        except:
            raise RuntimeError('bitcoind is not running.')
        self.testnet = True if (info['testnet']) else False

    def getbestblockhash(self):
        """ Return hash of the most recent block in best-block-chain. """
        try:
            return x(self._call('getbestblockhash')).encode('hex')
        except JSONRPCError as ex:
            raise IndexError('%s.getblockhash(): %s (%d)' %
                             (self.__class__.__name__, ex.error['message'], ex.error['code']))

    def getblock(self, block_hash):
        """ Return the verbose JSON presentation of a block.
            This overwrites python-bitcoinlib's getblock method, which
            returns a CBlock instead. For our use case, the JSON presentation
            is better-suited. """
        try:
            return self._call('getblock', block_hash, True)
        except JSONRPCError as ex:
            raise IndexError('%s.getblock(): %s (%d)' %
                             (self.__class__.__name__, ex.error['message'], ex.error['code']))

    def getrawtransaction(self, txid, verbose=True):
        try:
            return self._call('getrawtransaction', txid, 1 if verbose else 0)
        except JSONRPCError as ex:
            if (self.testnet):
                return None
            else:
                raise IndexError('%s.getrawtransaction(): %s (%d)' %
                                 (self.__class__.__name__, ex.error['message'], ex.error['code']))

    def sendrawtransaction(self, tx):
        try:
            return self._call('sendrawtransaction', str(tx))
        except JSONRPCError as ex:
            """ Error -25 is for attempted double spending (sending the same transaction twice).
                This is deliberately done by CoinParty as mixing peers broadcast each
                transaction concurrently. Thus, we just consume this error. """
            if (ex.error['code'] != -25):
                raise IndexError('%s.sendrawtransaction(): %s (%d)\nTransaction was:\n%s' %
                                 (self.__class__.__name__, ex.error['message'], ex.error['code'], str(tx)))


# Define usage of mainnet or testnet
SelectParams('testnet' if mstate.usingTestnet() else 'mainnet')

try:
    bitcoind = Proxy()
except BaseException as e:
    from sys import exit
    log.critical('Could not initialize bitcoind proxy: ' + str(e))
    exit(1)


def transaction_confirmed(txid, confirmations=6):
    """ Check whether the transaction referred to by txid has sufficiently
        many confirmations. """
    try:
        tx = bitcoind.getrawtransaction(txid)
        return True if (tx['confirmations'] >= confirmations) else False
    except:
        return False
