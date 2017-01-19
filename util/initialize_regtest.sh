#!/bin/bash

# CoinParty - Regtest Initialization
# Initialize fresh regtest block chain
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


blockcount=1500

echo -n "Stopping bitcoind if running..."
bitcoin-cli -regtest stop 2>&1 1>/dev/null
echo -n "wait 5 secs..."
sleep 5
echo "done!"
echo -n "Deleting ~/.bitcoin/regtest folder..."
rm -rf ~/.bitcoin/regtest 2>&1 1>/dev/null
echo "done!"
echo -n "Starting bitcoind..."
bitcoind -regtest -daemon 2>&1 1>/dev/null
echo -n "wait 15 secs..."
sleep 15
echo "done!"
echo -n "Creating accounts for Alice, Bob, and Charly..."
bitcoin-cli -regtest getaccountaddress "alice" 2>&1 1>/dev/null
bitcoin-cli -regtest getaccountaddress "bob" 2>&1 1>/dev/null
bitcoin-cli -regtest getaccountaddress "charly" 2>&1 1>/dev/null
echo "done!"
echo -n "Mining ${blockcount} blocks to generate usable bitcoins..."
bitcoin-cli -regtest generate ${blockcount} 2>&1 1>/dev/null
echo "done!"
echo "Everything finished."
