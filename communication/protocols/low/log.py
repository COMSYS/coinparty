""" CoinParty - Logger
    A wrapper for Python's logging class; each module uses a dedicated logger.

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

import logging
from twisted.python.failure import Failure


class Logger():

    def __init__(self, name):
        logging.basicConfig()
        self.log = logging.getLogger(name)
        self.log.setLevel(1)  # FIXME: Make logging level configurable (now: circular dependency)

    def setLevel(self, lvl):
        return self.log.setLevel(lvl)

    def info(self, msg, *args, **kwargs):
        return self.log.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        return self.log.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        return self.log.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        return self.log.critical(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        return self.log.debug(msg, *args, **kwargs)

    def log(self, lvl, msg, *args, **kwargs):
        return self.log.log(lvl, msg, *args, **kwargs)


""" Shord-hand helper functions for logging out of Deferreds by passing through whatever input arrived. """


class DeferredLogger():

    _deferred_logger = Logger('deferred')

    @staticmethod
    def _get_error_str(cv):
        return str(cv.getErrorMessage() if isinstance(cv, Failure) else cv)

    @staticmethod
    def info(cv, msg, *args, **kwargs):
        DeferredLogger._deferred_logger.info(msg, *args, **kwargs)
        return cv

    @staticmethod
    def warning(cv, msg, *args, **kwargs):
        DeferredLogger._deferred_logger.warning(msg, *args, **kwargs)
        return cv

    @staticmethod
    def error(cv, msg, *args, **kwargs):
        error_msg = msg + '\n' + DeferredLogger._get_error_str(cv)
        DeferredLogger._deferred_logger.error(error_msg, *args, **kwargs)
        return cv

    @staticmethod
    def critical(cv, msg, *args, **kwargs):
        error_msg = msg + '\n' + DeferredLogger._get_error_str(cv)
        DeferredLogger._deferred_logger.critical(error_msg, *args, **kwargs)
        return cv

    @staticmethod
    def debug(cv, msg, *args, **kwargs):
        DeferredLogger._deferred_logger.debug(msg, *args, **kwargs)
        return cv

    @staticmethod
    def log(cv, lvl, msg, *args, **kwargs):
        DeferredLogger._deferred_logger.log(lvl, msg, *args, **kwargs)
        return cv

    @staticmethod
    def debug_res(cv, msg, *args, **kwargs):
        DeferredLogger._deferred_logger.debug(msg + str(cv), *args, **kwargs)
        return cv
