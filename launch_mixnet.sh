#!/bin/bash

# CoinParty - Launch Mixnet
# Start all mixing peers (according to mixnets.conf) in a tmux session.
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

mpl="$(sed -E '/\[mixing_peers\]/,/^ *\[[^\[].*\]/!d' mixnets.conf | grep "\[\[" | tr -d "[]")"
mps="$(for mp in $mpl; do echo $mp; done | sort)"

first=1
for mp in $(echo $mps | sort); do
    echo "Doing $mp"
    if [ $first -eq 1 ]; then
        tmux new-session -d -s coinparty
        tmux select-window -t coinparty:0
        tmux set-option -g remain-on-exit on
        tmux rename-window 'CoinParty Mixpeers'
        tmux send-keys "python MixingPeer.py ${mp}" C-m
    else
        tmux split-window -t coinparty:0 # exec echo \"I am mixing peer: ${mp}\"
        tmux send-keys -t coinparty:0 "python MixingPeer.py ${mp}" C-m
        tmux respawn-pane
    fi
    first=0
done
tmux select-layout -t coinparty tiled
tmux attach -t coinparty
