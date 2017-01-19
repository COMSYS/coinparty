#!/bin/bash

# CoinParty - Regtest Account Setup
# This script provides the accounts alice, bob, and charly with (at least)
# 5 BTC.
# 
# Copyright (C) 2016 Roman Matzutt, Henrik Ziegeldorf
# 
# This file is part of CoinParty.
# 
# CoinParty is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# CoinParty is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with CoinParty.  If not, see <http://www.gnu.org/licenses/>.

bal=$(bitcoin-cli -regtest getbalance "" 2>&1)
if [ $(echo -n $bal | grep -qe "^error:"; echo -n $? ) == "0" ]; then
    echo "Bitcoind is not yet running. Starting it up."
fi
while [ $(echo -n $bal | grep -qe "^error:"; echo -n $? ) == "0" ]; do
    bitcoind -regtest -daemon > /dev/null 2>&1
    bal=$(bitcoin-cli -regtest getbalance "none" 2>&1)
    sleep 1
done

echo $bal

if [ "$(echo "${bal} < 15.0" | bc)" = "1" ]; then
    echo "Not enough Bitcoins. Mining new block."
    bitcoin-cli -regtest generate 1
fi

for peer in "alice" "bob" "charly"; do
    #addr="$(bitcoin-cli -regtest getnewaddress "${peer}" 2>/dev/null)"
    bitcoin-cli -regtest move "" "${peer}" 5.0 2>&1 1>/dev/null
done

# Confirm transactions.
bitcoin-cli -regtest generate 6 2>&1 1>/dev/null
