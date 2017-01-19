""" CoinParty - Crypto State
    This state holds cryptographic information such as the parameters of
    Bitcoin's elliptic curve and the peer's key pair.

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

import pyelliptic


class CryptoState(object):
    def __init__(self):
        self._prvkey = None
        self._pubkey = None
        self._crypter = None

    def setCryptoParams(self, private_key_hex, public_key_hex):
        try:
            # Do not decode here as the hex presentation is used more often (decode only for initializing ECC)
            self._prvkey = private_key_hex
            self._pubkey = public_key_hex
        except TypeError:
            raise TypeError('Could not decode keys.')
        self._crypter = pyelliptic.ECC(
            curve='secp256k1',
            privkey=self._prvkey.decode('hex'),
            pubkey=self._pubkey.decode('hex')
        )
        return

    def getPublicKey(self):
        return self._pubkey

    def getPrivateKey(self):
        return self._prvkey

    def getCrypter(self):
        return self._crypter
