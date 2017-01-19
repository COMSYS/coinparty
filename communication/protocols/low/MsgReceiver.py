""" CoinParty - Message Receiver
    A twisted protocol to trigger callbacks once a message corresponding to
    our binary P2P protocol is being received.

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

from twisted.internet import protocol
import Requests as req

from log import Logger


class MsgReceiver(protocol.Protocol):
    """ Provide a basic class for receiving complete JSON messages and nothing else. """

    def __init__(self):
        """ Initialize state values when a new object is instantiated. """

        # Initialize logger to log on behalf of respective derived protocol
        class_name = self.__class__.__name__
        if (class_name == 'P2pServer'):
            log_name = 'p2p_server'
        elif (class_name == 'P2pClient'):
            log_name = 'p2p_client'
        else:
            log_name = 'unkown_proto'

        self.log = Logger(log_name)

        self.buffer = ''
        self.expected_length = 0
        self.last_msg = None

    def respond(self, response):
        """ Respond to the input peer. """
        self.transport.write(response)


#####################################################################
#
#       Events
#
#####################################################################

    def msgReceived(self, msg_bin):
        """ Function stub to be implemented by deriving classes. """
        pass

    def dataReceived(self, data):
        """ Receive chunks of data until (hopefully) a valid message has been received """

        self.buffer += data
        while True:
            if (self.expected_length == 0):  # We are inspecting a fresh packet
                if (len(self.buffer) < 12):  # Length not completely received... wait for next data chunk
                    return
                self.expected_length = req.MessageHandler.getLength(self.buffer)
            else:
                if (len(self.buffer) >= self.expected_length):  # We have received at least one complete message
                    self.last_msg = self.buffer[:self.expected_length]
                    self.msgReceived(self.last_msg)
                    self.buffer = self.buffer[self.expected_length:]
                    self.expected_length = 0
                else:  # Message yet incomplete; wait for next chunk
                    return
