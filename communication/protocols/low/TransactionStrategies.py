""" CoinParty - Transaction Splitting Strategies
    This file defines strategies for scheduling the transactions returning
    the mixed bitcoins to the input users.

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

from copy import copy
from decimal import Decimal

from log import Logger
log = Logger('split')

rnd_resolution = 0xFFFFFFFFFF


def randomfloat(prng):
    return prng.randint(0, rnd_resolution) / (rnd_resolution * 1.0)

""" Strategies for splitting bitcoin values """

split_values = [1000, 200, 100, 10, 1]  # Sorted decreasingly
split_likely = [0.13, 0.19, 0.11, 0.45, 0.12]


def _is_integer(v):
    return v == v.to_integral_value()


def _split_strategy_single_transaction(bitcoin_value, _):  # Do not use prng variable
    test_val = 1000 * bitcoin_value
    if (not (_is_integer(test_val) and test_val in split_values)):
        log.critical('Detected disallowed Bitcoin value!')
        raise ValueError('value_not_allowed')
    log.debug('Split: ' + str([bitcoin_value]))
    return [bitcoin_value]


def _split_strategy_divide_and_fill(bitcoin_value, prng):
    split = []
    remaining = copy(bitcoin_value)

    sv = copy(split_values)
    sl = copy(split_likely)
    remaining = 1000 * remaining

    # Check that number can be split (i.e. smallest split amount divides the value)
    if (not _is_integer(remaining / Decimal(sv[-1]))):  # 1.0 needed as int has no method is_integer
        raise ValueError('value_not_splittable')  # TODO: Perform check during bootstrapping

    remaining = int(remaining)

    while (remaining > 0):
        while (len(sv) > 0 and remaining < sv[0]):  # Exclude too large values
            log.debug('Remaining: ' + str(remaining) + ' => Removing value ' + str(sv[0]))
            l = sl[0]
            del sv[0]
            del sl[0]
            for i in xrange(0, len(sv)):
                sl[i] = sl[i] / (1.0 - l)
        r = randomfloat(prng)
        s = sl[0]
        i = 0
        while (r > s):
            log.debug('rem: ' + str(remaining) + '; i: ' + str(i) + '; r: ' + str(r) + '; s: ' + str(s))
            try:
                i += 1
                s += sl[i]
            except:
                log.error('Error: ' + str(sl))
                break
        split.append(sv[i])
        remaining -= sv[i]

    probs = []
    for i in xrange(0, len(split_values)):
        probs.append(((1.0 * len(filter(lambda x: x == split_values[i], split))) / len(split), split_likely[i]))
    split = map(lambda x: x / 1000.0, split)
    log.debug('Split before shuffling:\n' + str(split))
    prng.shuffle(split)
    log.debug('Split after shuffling:\n' + str(split))

    log.debug('Probability distributions:\n' + str(probs))
    log.debug('Probability derivation:\n' + str([x[0] - x[1] for x in probs]))
    log.debug('Split sum: ' + str(sum(split)))
    return split

""" Strategies for obtaining a streaming schedule for one input peer """


def _schedule_strategy_fixed(split_length, mixing_window_mins, _):  # Do not used prng variable
    schedule = []
    t = 0.0
    interval = (mixing_window_mins * 60.0) / split_length
    for _ in xrange(0, split_length):
        schedule.append(t)
        t += interval
    return schedule


def _schedule_strategy_random(split_length, mixing_window_mins, prng):
    schedule = []
    for _ in xrange(0, split_length):
        schedule.append(randomfloat(prng) * 60 * mixing_window_mins)
    schedule.sort()  # We need a monotonically increasing list, otherwise break transaction creation
    return schedule

splitMixingAmount = _split_strategy_single_transaction
defineStreamingSchedule = _schedule_strategy_random
