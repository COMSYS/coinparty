""" CoinParty - Shuffling Protocol
    This protocol perfoms the actual mixing and checks its correctness.

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

from low.constants import hash_order, hash_modulus
import low.Requests as req
from low.Transaction import BroadcastTransaction
from low.smpc.WrapperSmpcValue import WrapperSmpcValue
import hashlib
from Crypto.Random.Fortuna.FortunaGenerator import AESGenerator as SeedablePrngGenerator
from Crypto.Random.random import StrongRandom
from Crypto.Random import random
from twisted.internet.defer import Deferred

from low.log import Logger
log = Logger('shuffling')


def shuffling_phase(_, state):
    """ Implementation of the shuffling phase. """

    def _fire_shuffle_broadcast(v, addresses, sender_rank):
        state.shuffle.receivedAddrBroadcast(addresses, sender_rank)
        return v

    def checksumToString(checksum):
        return '{0:0{1}x}'.format(int(checksum) % hash_modulus, 64)

    def recombineChecksum(escrows, layer):
        checksum_share = 0
        for escrow in escrows:
            checksum_share = (checksum_share + escrow['hash_share'][layer]) % hash_order
        checksum_share_wrapped = WrapperSmpcValue(state)
        checksum_share_wrapped.initialize(checksum_share)
        checksum = state.smpc.newValue('rec', state, 'c', layer)
        checksum.initialize(checksum_share_wrapped, order=hash_order)
        checksum_deferred = checksum.getPublicValue()
        checksum_deferred.addCallback(checksumToString)
        checksum_deferred.addCallback(state.shuffle.storeChecksum, index=layer)
        return checksum_deferred

    def computeReferenceChecksum(layered_encryption):
        output_checksum = 0
        for entry in layered_encryption:
            hash_str = hashlib.sha256(entry).hexdigest()
            output_checksum = (output_checksum + int(hash_str, 16)) % hash_order
        output_checksum = checksumToString(output_checksum)
        return output_checksum

    def compareChecksums(checksum, reference_checksum):
        log.debug('Hashshare Checksum: ' + str(checksum))
        log.debug('LocalAddr Checksum: ' + str(reference_checksum))
        if (checksum != reference_checksum):
            raise ValueError('checksums_dont_match')

        log.debug('Checksum check was successful!')
        return checksum

    def orderLexicographically(list):
        return sorted(list)

    def computeFinalPermutation(output_addresses, checksum):
        # Compute hex presentation of checksum
        seed = checksum.decode('hex')

        """ Create a PRNG based on Crypto.random.random, but with seedable input
            (instead of /dev/urandom). """
        prng_input = SeedablePrngGenerator()
        prng_input.reseed(seed)
        log.debug('Seed: ' + seed.encode('hex'))
        prng = StrongRandom(randfunc=prng_input.pseudo_random_data)

        prng.shuffle(output_addresses)
        return output_addresses

    def decryptionMixnet(addresses):
        """ Decryption mixnet operation. Consists of removing an encryption
            layer from each output address in the output address array, and
            then permutating the addresses. """
        log.debug('Entered output address processing.')

        def decryptAddressLayer(addresses):
            crypter = state.crypto.getCrypter()
            result = []
            for address in addresses:
                plain = crypter.decrypt(address, ciphername='aes-256-cbc')
                result.append(plain)
            return result

        def shuffleAddresses(addresses):
            """ Create a shuffled copy (only references!) of the encrypted output addresses. """
            indices = [i for i in xrange(0, len(addresses))]
            random.shuffle(indices)
            result = []
            for index in indices:
                result.append(addresses[index])
            return result

        decrypted_addresses = decryptAddressLayer(addresses)
        shuffled_addresses = shuffleAddresses(decrypted_addresses)
        return shuffled_addresses

    def broadcastShufflingResult(addresses):
        crypter = state.crypto.getCrypter()
        seq = state.transactions.getNextSequenceNumber()
        msg = req.addr.encode(state.mixnet.getRank(), seq, crypter, addresses)
        peers = state.mixnet.getConnectedMixpeers()
        # Create deferred for broadcast, fired after the last response is received
        broadcast_deferred = state.transactions.addTransaction(
            BroadcastTransaction(state.mixnet.getRank(), peers, msg, seq, None)
        )
        return broadcast_deferred

    def receivedAddrBroadcast(params):
        (addresses, sender_rank) = params

        def errorDummy(f):
            log.critical('Error occurred: ' + str(f.getErrorMessage()))
            log.critical('I SHOULD go into error reversion phase, but I won\'t.')
            return f

        def fireShufflingDeferred(v):
            state.shuffle.fireShufflingDeferred()
            return v

        def checksumRoutine(_):
            deferred = recombineChecksum(state.input.getAssignedEscrows(), sender_rank)
            reference_checksum = computeReferenceChecksum(addresses)
            deferred.addBoth(compareChecksums, reference_checksum=reference_checksum)
            return deferred

        def decideAction(checksum):

            if (sender_rank == state.mixnet.getRank() - 1):  # It's my turn
                shuffled_addresses = decryptionMixnet(addresses)
                deferred = broadcastShufflingResult(shuffled_addresses)
                deferred.addCallback(_fire_shuffle_broadcast, shuffled_addresses, state.mixnet.getRank())
                return deferred

            if (state.mixnet.isLastMixpeer(sender_rank)):  # I have received the plaintext addresses => finalize!
                ordered_addresses = orderLexicographically(addresses)
                shuffled_addresses = computeFinalPermutation(ordered_addresses, checksum)
                state.input.assignOutputAddresses(shuffled_addresses)
                state.shuffle.fireShufflingDeferred()
                return

        deferred = Deferred()
        # We're at an intermediate peer, not the one starting the mixing => We have a predecessor to check
        if (sender_rank >= 0):
            deferred.addCallback(checksumRoutine)
        deferred.addCallback(decideAction)
        deferred.addErrback(errorDummy)
        deferred.callback(None)
        return deferred

    """ The actual implementation starts here. """

    state.shuffle.addAddrDeferredCallback(receivedAddrBroadcast)
    shuffling_deferred = state.shuffle.getShufflingDeferred()

    state.shuffle.initialized()

    """ "If I am the first peer, start mixing based on input user submissions. """
    if (state.mixnet.getRank() == 0):
        addresses = state.input.getEncryptedOutputAddresses()
        addresses_decrypted = decryptionMixnet(addresses)
        deferred = broadcastShufflingResult(addresses_decrypted)
        deferred.addCallback(_fire_shuffle_broadcast, addresses_decrypted, state.mixnet.getRank())

    return shuffling_deferred
