""" CoinParty - SMCP Value Store
    A data structure holding all SMPC values computed or being computed in one
    session.

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

from MultiplicationSmpcValue import MultiplicationSmpcValue
from RecombinationSmpcValue import RecombinationSmpcValue
from JfDkgSmpcValue import JfDkgSmpcValue
from NewDkgSmpcValue import NewDkgSmpcValue
from WrapperSmpcValue import WrapperSmpcValue
from ConstantMultiplicationSmpcValue import ConstantMultiplicationSmpcValue


class SmpcStore(object):
    def __init__(self):
        self._values = dict()

    def __getstate__(self):
        state = self._values
        return state

    def __setstate__(self, state):
        self._values = state

    def newValue(self, smpc_algorithm, state, id, index=0):
        """ If the value already exists, return the existing value instead of
            creating a new one. """
        if (id in self._values.keys() and index < len(self._values[id]) and self._values[id][index] is not None):
            return self._values[id][index]

        try:
            (smpc_class, active) = self.getAlgorithm(smpc_algorithm, get_active=True)
        except ValueError:
            print('Entering error case.')
            print(str(smpc_algorithm))
            raise

        if (active):
            smpc_value = smpc_class(id, index, state)
        else:
            smpc_value = smpc_class(state)

        return self.addValue(smpc_value, id, index)

    def addValue(self, smpc_value, id, index):

        try:
            array = self._values[id]
        except KeyError:
            array = [None] * (index + 1)
            self._values[id] = array

        try:
            check = array[index]
        except IndexError:
            array += [None] * (index + 1 - len(array))
            check = None

        if (check is not None):
            raise RuntimeError('smpc_value_exists')

        array[index] = smpc_value
        return smpc_value

    def getValue(self, id, index=0):
        try:
            return self._values[id][index]
        except:
            return None

    @staticmethod
    def getAlgorithm(algorithm_name, get_active=False):
        if (algorithm_name == 'jfdkg'):
            classname = JfDkgSmpcValue
            is_active = True
        elif (algorithm_name == 'dkg'):
            classname = NewDkgSmpcValue
            is_active = True
        elif (algorithm_name == 'mul'):
            classname = MultiplicationSmpcValue
            is_active = True
        elif (algorithm_name == 'rec'):
            classname = RecombinationSmpcValue
            is_active = True
        elif (algorithm_name == 'wrap'):
            classname = WrapperSmpcValue
            is_active = False
        elif (algorithm_name == 'cmul'):
            classname = ConstantMultiplicationSmpcValue
            is_active = False
        else:
            import traceback
            print traceback.format_exc()
            print(str(algorithm_name))
            raise ValueError('algorithm_unknown')

        if (get_active):
            return (classname, is_active)
        else:
            return classname
