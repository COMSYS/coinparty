""" CoinParty - Exceptions
    Custom exception types.

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


class ComplainError(Exception):
    def __init__(self, message, ranks):
        super(ComplainError, self).__init__(message)
        self.ranks = ranks


class ThresholdError(Exception):
    pass


class RequestError(Exception):
    pass


class AbstractClassError(Exception):
    pass


class CancelError(Exception):
    pass


class StopError(Exception):
    pass
