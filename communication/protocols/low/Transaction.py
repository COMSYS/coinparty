""" CoinParty - Transaction Handler
    A handler for transactions of P2P messages. Transactions are required
    whenever we wait for any message, e.g. a response or additional messages
    during a consistent broadcast.

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
from twisted.internet.defer import Deferred
from twisted.python.failure import Failure
import Requests as req
from exceptions import StopError
from log import Logger
log = Logger('low_transaction')
log.setLevel(0)

#####################################################################
#
#       Transaction Base Functionality
#
#####################################################################


class Transaction(object):
    """ A transaction is a special-purpose wrapper for twisted's Deferreds.
        A transaction consists of a set of requests the P2P client of a Mixing Peer sends to a variable number of
        P2P servers of other Mixing peers. For each request, a sequence number is stored. The Mixing Peer expects to
        see each sequence number once in responses received by its P2P server.
        Once each expected response has been received and processed, an internal Deferred is fired.
        The Deferred's callback-adding functions are adopted by the Transaction interface.

        Note: Using the Transaction object after the transaction has concluded, i.e., the Deferred has been fired,
              produces undefined behavior and is discouraged.
    """

    def _standard_callback(self, _):
        """ Binds the result fetcher of a transaction to the remaining callback chain. """
        return self._value if (self._is_positive) else Failure(RuntimeError(self._value))

    def __init__(self, seq, result_fetcher, opt=None):
        """ Initialize a transaction. Sequence numbers of expected responses must be known beforehand.
            Parameters:
            - peer_rank         Rank where to send the request to
            - msg               Dictionary containing the request's parameters
            - state             State object belonging to the transaction
            - result_fetcher    A function that aggregates the result from all received responses.
                                This function is called each time a sequence number from the pending list is being
                                deleted.
                                The result_fetcher MUST have the following signature:
                                - response     The response from the remote P2P server
                                - value        The current result of the transaction to be updated
                                - is_positive  States whether or not the current result is positive
                                - opt          An optional parameter used for whatever additional data is needed
                                The result_fetcher MUST return a dictionary of the form:
                                {'is_positive':True/False, 'value':val}
            - opt               A constant piece of additional information for the result_fetcher
        """
        self._sequence_number = seq
        self._deferred = Deferred()
        self._deferred.addBoth(self._standard_callback)
        self._result_fetcher = result_fetcher
        self._value = None
        self._is_positive = False
        self._opt = opt
        self._transdict = None  # set when added to Transaction Store
        if (result_fetcher is None):
            self._is_positive = True  # Never call errback...
            self._fireDeferred()

    def _fireDeferred(self):
        """ Fire the deferred and thereby end transaction. Do not use the transaction afterwards. """
        self._deferred.addBoth(self._killMe)
        self._deferred.callback(None)

    def _killMe(self, v):
        """ Remove concluded transactions that are managed via the transaction
            store (should be all of them). Otherwise, they clog RAM. """
        if (self._transdict is not None and self._sequence_number in self._transdict.keys()):
            self._transdict.pop(self._sequence_number, None)
        return v

    def getSequenceNumber(self):
        return self._sequence_number

    def receivedResponse(self, response):
        if (self._deferred.called):
            log.warning('Transaction already concluded. Ignoring response.')
            result = None
        elif (self._result_fetcher is None):
            result = None
        else:
            result = self._result_fetcher(response, self._value, self._is_positive, opt=self._opt)
        try:
            rank = response['rank']
        except KeyError:
            rank = None
        return (rank, result)

    # Deferred wrapper functions

    def addCallbacks(self, callback, errback=None, callbackArgs=None, callbackKeywords=None, errbackArgs=None, errbackKeywords=None):
        return self._deferred.addCallbacks(callback, errback=errback, callbackArgs=callbackArgs, callbackKeywords=callbackKeywords, errbackArgs=errbackArgs, errbackKeywords=errbackKeywords)

    def addCallback(self, callback, *args, **kw):
        return self._deferred.addCallback(callback, *args, **kw)

    def addErrback(self, errback, *args, **kw):
        return self._deferred.addErrback(errback, *args, **kw)

    def addBoth(self, callback, *args, **kw):
        return self._deferred.addBoth(callback, *args, **kw)

#####################################################################
#
#       Singlecast Transactions
#
#####################################################################


class SingleRequestTransaction(Transaction):

    def __init__(self, my_rank, peer, msg, seq, result_fetcher, opt=None):
        """ Additional parameters to base class:
            - peer_rank    Rank of the recipient peer of the transaction
            - msg          Message to be sent to the peer """
        super(SingleRequestTransaction, self).__init__(seq, result_fetcher, opt)
        self._peer_rank = peer['rank']
        peer['instance'].request(msg)

    def receivedResponse(self, response):
        (rank, result) = super(SingleRequestTransaction, self).receivedResponse(response)
        if (result is None or rank is None):
            return
        if (rank != self._peer_rank):
            raise RuntimeError('unexpected_peer_response')
        self._value = result['value']
        self._is_positive = result['is_positive']
        self._fireDeferred()
        return

#####################################################################
#
#       Broadcast Transactions
#
#####################################################################


class BroadcastTransaction(Transaction):
    def __init__(self, my_rank, peers, msg, seq, result_fetcher, opt=None):
        super(BroadcastTransaction, self).__init__(seq, result_fetcher, opt)
        self._expected_responses = [peer['rank'] for peer in peers]
        for peer in peers:
            peer['instance'].request(msg)

    def receivedResponse(self, response):
        (rank, result) = super(BroadcastTransaction, self).receivedResponse(response)
        if (result is None or rank is None):
            return

        try:
            index = self._expected_responses.index(rank)
        except ValueError:
            raise RuntimeError('peer_already_responded')

        del self._expected_responses[index]
        self._value = result['value']
        self._is_positive = result['is_positive']
        if (len(self._expected_responses) == 0):
            self._fireDeferred()

#####################################################################
#
#       Eachcast Transactions
#
#       (Each peer receives one respective private value)
#
#####################################################################


class EachcastTransaction(Transaction):
    def __init__(self, my_rank, peers, msgs, seq, result_fetcher, opt=None):
        super(EachcastTransaction, self).__init__(seq, result_fetcher, opt)
        self._expected_responses = [peer['rank'] for peer in peers]
        if (len(msgs) != len(self._expected_responses)):
            raise RuntimeError('msg_number_mismatch')
        for i in xrange(0, len(msgs)):
            msg = msgs[i]
            peers[i]['instance'].request(msg)

    def receivedResponse(self, response):
        (rank, result) = super(BroadcastTransaction, self).receivedResponse(response)
        if (result is None or rank is None):
            return
        try:
            index = self._expected_responses.index(rank)
        except ValueError:
            raise RuntimeError('peer_already_responded')

        del self._expected_responses[index]
        self._value = result['value']
        self._is_positive = result['is_positive']
        if (len(self._expected_responses) == 0):
            self._fireDeferred()

#####################################################################
#
#       Reliable Broadcast Transactions
#
#####################################################################


class ReliableBroadcastTransaction(Transaction):
    def __init__(self, my_rank, peers, msg, n, t, seq, delay_deferred=None, active=True):
        """ msg is either message to broadcast (active == True) or ignored
            (active == False). """
        def dummy_result_fetcher(x):
            return x
        super(ReliableBroadcastTransaction, self).__init__(seq, dummy_result_fetcher, None)
        self._n = n
        self._t = t
        # ... + ((n + t + 1) % 2) to resemble ceil()
        self._t_echo = (self._n + self._t + 1 + ((self._n + self._t + 1) % 2)) / 2
        self._echos = [None] * self._n
        self._readys = [None] * self._n
        self._ready_sent = False
        self._msg = None
        self._send_received = False
        self._active = active
        self._peers = peers
        self._rank = my_rank
        self._delay_deferred = delay_deferred
        self._callback_defined = False
        self._is_positive = True
        if (self._active):  # I am the sender of a broadcast
            self._msg = msg
            self.sendSend()

    @staticmethod
    def _hist(array):
        """ Determine the most-occuring value in array and return it as well
            as its number of occurences. """
        bins = []
        counts = []
        for x in array:
            if (x is None):
                continue
            if (x not in bins):
                bins.append(x)
                counts.append(1)
            else:
                i = bins.index(x)
                counts[i] += 1
        try:
            i = counts.index(max(counts))
        except:
            return (0, None)
        return (counts[i], bins[i])

    def getEchoNumber(self):
        return self._hist(self._echos)

    def getReadyNumber(self):
        return self._hist(self._readys)

    def defineCallback(self, request_handler, smpc_value):
        if (self._callback_defined):
            return
        self._deferred.addCallback(request_handler.processRequest, smpc_value)
        self._callback_defined = True
        log.debug('Now the callback is defined.')
        return

    def _killMe(self, v):
        """ Replace this transaction with a reduced dummy transaction.
            This type of transaction will just consume delayed messages
            that were not needed (unneeded echos, readys) and will completely
            be  removed once every expected additional message has been
            received. """
        if (self._transdict is not None and self._sequence_number in self._transdict.keys()):
            t = KilledReliableBroadcastTransaction(
                self._transdict,
                self._sequence_number,
                self._send_received,
                filter(lambda i: self._echos[i] is None, xrange(self._n)),
                filter(lambda i: self._readys[i] is None, xrange(self._n))
            )
            self._transdict[self._sequence_number] = t
        return v

    def broadcast(self, msg):
        def _delayed_request(v, rank, msg):
            peer_p2p = next((peer['instance'] for peer in self._peers if peer['rank'] == rank))
            peer_p2p.request(msg)
            return v
        for peer in self._peers:
            if (peer['instance'] is None):
                if (self._delay_deferred is None):
                    log.error('I should delay a Bracha message, but have no delay deferred.')
                else:
                    log.debug('Delaying reaction to prematurely received Bracha message.')
                    self._delay_deferred.addCallback(_delayed_request, rank=peer['rank'], msg=msg)
            else:
                peer['instance'].request(msg)
        return

    def sendSend(self):
        msg = dict()
        msg['msg'] = self._msg['msg']
        msg['rank'] = self._rank
        msg['seq'] = self._sequence_number
        msg['type'] = 's'
        msg['m'] = self._msg
        self.broadcast(msg)
        self.receivedSend(self._rank, msg['m'])
        return

    def receivedSend(self, rank, msg):
        if (self._send_received):  # Ignore subsequent send messages
            return None
        log.debug('bracha:Received send.')
        """ Now the message is known and prior received ECHOs and READYs can
            be evaluated. """
        self._send_received = True
        self._msg = msg
        """ Send echo to all connected players except sender. """
        self.sendEcho()

    def sendEcho(self):
        msg = dict()
        msg['rank'] = self._rank
        msg['seq'] = self._msg['seq']
        msg['type'] = 'e'
        msg['m'] = self._msg
        msg['msg'] = self._msg['msg']
        self.broadcast(msg)
        self.receivedEcho(self._rank, msg['m'])
        return

    def receivedEcho(self, rank, msg):
        """ When SEND has not yet been received, store the message that is sent
            via the ECHO message. Otherwise peers might exchange it... """
        self._echos[rank] = msg
        (number_echos, majority_msg) = self.getEchoNumber()
        log.debug('bracha:Received echo. Echo count: ' + str(number_echos) + ' / ' + str(self._t_echo))
        if (number_echos == self._t_echo and not self._ready_sent):
            self._msg = majority_msg
            self.sendReady()
        return None

    def sendReady(self):
        log.debug('bracha:Broadcasting ready.')
        if (self._ready_sent):
            return
        msg = dict()
        msg['rank'] = self._rank
        msg['seq'] = self._msg['seq']
        msg['type'] = 'r'
        msg['m'] = self._msg
        msg['msg'] = self._msg['msg']
        self.broadcast(msg)
        self._ready_sent = True
        self.receivedReady(self._rank, msg['m'])
        return

    def receivedReady(self, rank, msg):
        """ When SEND has not yet been received, store the message that is sent
            via the READY message. Otherwise peers might exchange it... """
        self._readys[rank] = msg
        (number_readys, majority_msg) = self.getReadyNumber()
        log.debug('bracha:Received ready. Ready count: ' + str(number_readys) + ' / ' + str(self._t + 1) + ' / ' + str(2 * self._t + 1))
        if (number_readys == self._t + 1 and not self._ready_sent):
            self._msg = majority_msg
            self.sendReady()
            return None
        elif (number_readys == 2 * self._t + 1):
            log.debug('bracha:Delivering.')
            log.debug('bracha:Message: ' + str(majority_msg))
            self._value = majority_msg
            self._fireDeferred()

    def receivedResponse(self, response):
        if (not ('type' in response.keys() and
                 'rank' in response.keys() and
                 'm' in response.keys())):  # Ignore bogus message
            log.error('Malformed bracha message. Information missing. Ignoring message')
            return None
        elif (response['type'] == 's'):  # Received a send message
            return self.receivedSend(response['rank'], response['m'])
        elif (response['type'] == 'e'):  # Received an echo message
            return self.receivedEcho(response['rank'], response['m'])
        elif (response['type'] == 'r'):
            return self.receivedReady(response['rank'], response['m'])
        else:  # Ignore all other messages
            return None

#####################################################################
#
#       Zombie Reliable Broadcast Transaction
#
#####################################################################


class KilledReliableBroadcastTransaction(object):
    """ Dummy class to minimize state in Transaction store. """
    def __init__(self, transdict, seq, send_received, remaining_echos, remaining_readys):
        self._transdict = transdict
        self._seq = seq
        self._send = send_received
        self._echos = remaining_echos
        self._readys = remaining_readys

    def receivedResponse(self, response):
        if (not ('type' in response.keys() and
                 'rank' in response.keys())):  # Ignore bogus message
            log.error('Malformed bracha message. Information missing. Ignoring message')
            return
        elif (response['type'] == 's'):  # Received a send message
            self._send = True
        elif (response['type'] == 'e'):  # Received an echo message
            if (response['rank'] in self._echos):
                del self._echos[self._echos.index(response['rank'])]
        elif (response['type'] == 'r'):
            if (response['rank'] in self._readys):
                del self._readys[self._readys.index(response['rank'])]
        else:  # Ignore all other messages
            return

        """ No further message will arrive, thus kill the message completely. """
        if (self._send and len(self._echos) + len(self._readys) == 0):
            self._transdict.pop(self._seq, None)
        return

#####################################################################
#
#       Consistent Broadcast Transaction
#
#####################################################################


class ConsistentBroadcastTransaction(Transaction):
    def __init__(self, my_rank, my_crypt, peers, n, t, seq, msg=None, delay_deferred=None):
        """ msg is either message to broadcast or None (for passive peers). """
        def dummy_result_fetcher(x):
            return x
        super(ConsistentBroadcastTransaction, self).__init__(seq, dummy_result_fetcher, None)
        self._n = n
        self._t = t
        # ... + ((n + t + 1) % 2) to resemble ceil()
        self._t_echo = (self._n + self._t + 1 + ((self._n + self._t + 1) % 2)) / 2
        self._echos = [None] * self._n
        self._peers = peers
        self._rank = my_rank
        self._delay_deferred = delay_deferred
        self._callback_defined = False
        self._is_positive = True
        self._msg = msg
        self._crypt = my_crypt
        self._sender_rank = self._rank if self._msg is not None else None
        if (self._msg is not None):  # Send msg if given; msg == None implies passiveness
            self.sendSend()

    def getEchoNumber(self):
        return len(filter(lambda x: not (x is None or x is False), self._echos))

    def defineCallback(self, request_handler, smpc_value):
        def preprocessMessage(msg_bin, request_handler):
            rank = req.MessageHandler.getRank(msg_bin)
            crypt = self._crypt if (rank == self._rank) else next((peer['crypt'] for peer in self._peers if peer['rank'] == rank))
            if (not req.MessageHandler.checkSignature(msg_bin, crypt)):
                log.error('Signature check failed.')
            return request_handler.decode(msg_bin)

        if (self._callback_defined):
            return
        self._deferred.addCallback(preprocessMessage, request_handler=request_handler)
        self._deferred.addCallback(request_handler.processRequest, smpc_value)
        self._callback_defined = True
        log.debug('Now the callback is defined.')
        return

    def _killMe(self, v):
        """ Replace this transaction with a reduced dummy transaction.
            This type of transaction will just consume delayed messages
            that were not needed (unneeded echos, readys) and will completely
            be  removed once every expected additional message has been
            received. """
        if (self._transdict is not None and self._sequence_number in self._transdict.keys()):
            t = KilledConsistentBroadcastTransaction(
                self._transdict,
                self._sequence_number,
                filter(lambda i: self._echos[i] is None, xrange(self._n))
            )
            self._transdict[self._sequence_number] = t
        return v

    def _internal_singlecast(self, peer, msg):
        def _delayed_request(v, rank, msg):
            peer_p2p = next((peer['instance'] for peer in self._peers if peer['rank'] == rank))
            peer_p2p.request(msg)
            return v
        if (peer is None):
            log.error('cbroadcast:Invalid peer')
        elif (peer['instance'] is None):
            if (self._delay_deferred is None):
                log.error('I should delay a consistent broadcast message, but have no delay deferred.')
            else:
                log.debug('Delaying reaction to prematurely received consistent broadcast message.')
                self._delay_deferred.addCallback(_delayed_request, rank=peer['rank'], msg=msg)
        else:
            peer['instance'].request(msg)

    def singlecast(self, rank, msg):
        try:
            peer = next((peer for peer in self._peers if peer['rank'] == rank))
        except StopError:
            peer = None
        self._internal_singlecast(peer, msg)

    def broadcast(self, msg):
        for peer in self._peers:
            self._internal_singlecast(peer, msg)
        return

    def sendSend(self):
        msg = req.cbrc.encode(self._rank, self._sequence_number, self._crypt, req.cbrc.SEND, self._msg)
        self.broadcast(msg)
        sig = self._crypt.sign(self._msg)
        self._echos[self._rank] = sig
        return

    def receivedSend(self, rank, msg):
        if (self._sender_rank is not None):  # Ignore subsequent send messages
            return None
        log.debug('cbroadcast:Received send.')
        self._msg = msg
        self._sender_rank = rank
        """ Send signed echo to the sender. """
        self.sendEcho()

    def sendEcho(self):
        sig = self._crypt.sign(self._msg)
        msg = req.cbrc.encode(self._rank, self._sequence_number, self._crypt, req.cbrc.ECHO, sig)
        self.singlecast(self._sender_rank, msg)
        return

    def receivedEcho(self, rank, sig):
        crypt = next((peer['crypt'] for peer in self._peers if peer['rank'] == rank))
        if crypt.verify(sig, self._msg):  # Store received signature if valid
            self._echos[rank] = sig
        number_echos = self.getEchoNumber()
        log.debug('cbroadcast:Received echo. Echo count: ' + str(number_echos) + ' / ' + str(self._t_echo))
        if (number_echos == self._t_echo):
            self.sendFinal()
        return None

    def sendFinal(self):
        log.debug('cbroadcast:Broadcasting final message with signatures.')
        sigs = [[i, self._echos[i]] for i in xrange(len(self._echos)) if not (self._echos[i] is False or self._echos[i] is None)]
        msg = req.cbrc.encode(self._rank, self._sequence_number, self._crypt, req.cbrc.FINL, sigs)
        self.broadcast(msg)
        self.receivedFinal(sigs)
        return

    def receivedFinal(self, sigs):
        sigs_valid = True
        for sig in sigs:
            crypt = next((peer['crypt'] for peer in self._peers if peer['rank'] == sig[0])) \
                if sig[0] != self._rank else self._crypt
            if not crypt.verify(sig[1], self._msg):
                sigs_valid = False
                break
        if (sigs_valid):
            log.debug('cbroadcast:Delivering.')
            log.debug('cbroadcast:Message: ' + str(self._msg))
            self._value = self._msg
            self._fireDeferred()
        else:
            log.debug('cbroadcast:Signatures invalid.')

    def receivedResponse(self, response):
        if (not ('type' in response.keys() and
                 'rank' in response.keys())):  # Ignore bogus message
            log.error('cbroadcast:Malformed message. Information missing. Ignoring.')
            return None
        elif (response['type'] == 's'):  # Received a send message
            if (self._msg is not None):  # I am sender or already have received send, discard
                return None
            return self.receivedSend(response['rank'], response['m'])
        elif (response['type'] == 'e'):  # Received an echo message
            if (not ('s' in response.keys())):
                return None
            return self.receivedEcho(response['rank'], response['s'])
        elif (response['type'] == 'f'):
            if (not ('s' in response.keys()) or response['rank'] != self._sender_rank):
                return None
            return self.receivedFinal(response['s'])
        else:  # Ignore all other messages
            return None

#####################################################################
#
#       Zombie Consistent Broadcast Transaction
#
#####################################################################


class KilledConsistentBroadcastTransaction(object):
    """ Dummy class to minimize state in Transaction store. """
    def __init__(self, transdict, seq, remaining_echos):
        self._transdict = transdict
        self._seq = seq
        self._echos = remaining_echos

    def receivedResponse(self, response):
        try:
            if (not ('type' in response.keys() and
                     'rank' in response.keys())):  # Ignore bogus message
                log.error('cbroadcast:Malformed message. Information missing. Ignoring.')
                return
            elif (response['type'] == 'e'):  # Received an echo message
                if (response['rank'] in self._echos):
                    del self._echos[self._echos.index(response['rank'])]
            else:  # Ignore all other messages
                return None

            """ No further message will arrive, thus kill the message completely. """
            if (len(self._echos) == 0):
                self._transdict.pop(self._seq, None)
            return
        except BaseException as e:
            print('ERROR in killed trans: ' + str(e))
            return e

#####################################################################
#
#       Transaction Store
#
#####################################################################


class TransactionStore(object):
    def __init__(self):
        self._seq = random.getrandbits(32)
        self.transactions = {}

    def addTransaction(self, t):
        """ Add an existing transaction to the store of open transactions. """
        if (t._deferred.called):  # Transaction already concluded, no need to manage.
            return t._deferred
        t._transdict = self.transactions
        self.transactions[t.getSequenceNumber()] = t
        return t._deferred

    def findTransaction(self, seq):
        """ Search the list of open transactions for a specific sequence number and return the containing transaction. """
        return self.transactions[seq] if seq in self.transactions.keys() else None

    def getNextSequenceNumber(self):
        self._seq = self._seq + 1 if (self._seq < 0xFFFFFFFF) else 0
        return self._seq

    def receivedMessage(self, response):
        print('RECEIVED RESPONSE:\n' + str(response))
        try:
            seq = response['seq']
        except:
            raise ValueError('seq_missing')
        t = self.findTransaction(seq)
        if (t is None):
            raise ValueError('transaction_not_found')
        t.receivedResponse(response)
        return
