""" CoinParty - Request Handler
    Definition of our custom binary P2P protocol for CoinParty, as well
    as the corresponding request handlers.

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

from struct import Struct as struct
from exceptions import AbstractClassError
from log import Logger
log = Logger('req')
log.setLevel(0)


VERSION = 0x01
header_length = 85
sig_length = 72


class MessageTypes(object):
    """ CoinParty messages """
    HELO = 0x00  # Introduce new input user's data
    ADDR = 0x01  # Announce shuffled and decrypted output addresses
    ACKN = 0x0F  # Acknowledgement (hopefully can be designed out?)
    """ SMPC messages """
    MPCS = 0x10  # Secret value singlecast
    MPCP = 0x11  # Public value(sig_length - length) broadcast
    COMP = 0x12  # Complaint broadcast
    CMPR = 0x13  # Complaint reaction broadcast
    NCMP = 0x14  # No-complaint broadcast (to speed things up)
    """ Broadcast messages """
    RBRC = 0xF0  # Reliable Broadcast (Bracha)
    CBRC = 0xF1  # Consistent Broadcast (signature-based)

    smpc_msgs = [MPCS, MPCP, COMP, CMPR, NCMP]
    brdc_msgs = [RBRC, CBRC]

    @staticmethod
    def getString(msg_type):
        if (msg_type == MessageTypes.HELO):
            return 'helo'
        elif (msg_type == MessageTypes.ADDR):
            return 'addr'
        elif (msg_type == MessageTypes.ACKN):
            return 'ackn'
        elif (msg_type == MessageTypes.MPCS):
            return 'mpcs'
        elif (msg_type == MessageTypes.MPCP):
            return 'mpcp'
        elif (msg_type == MessageTypes.COMP):
            return 'comp'
        elif (msg_type == MessageTypes.CMPR):
            return 'cmpr'
        elif (msg_type == MessageTypes.NCMP):
            return 'ncmp'
        elif (msg_type == MessageTypes.RBRC):
            return 'rbrc'
        elif (msg_type == MessageTypes.CBRC):
            return 'cbrc'

#####################################################################
#
#       Abstract Message Handler
#
#####################################################################


class MessageHandler(object):

    """ Structure of the message header.
        Byte 1:      Version byte (0x01)
        Byte 2:      Message type
        Bytes 3,4:   Sender rank
        Bytes 5-8:   Sequence Number
        Bytes 9-12:  Packet length
        Bytes 13-82: ECDSA Signature """
    _msg = struct('>BBHII73s')
    _msg_length = struct('>I')

    @staticmethod
    def checkResponse(msg):
        errors = []
        if ('msg' not in msg.keys()):
            errors.append('msg_missing')
        if ('rank' not in msg.keys()):
            errors.append('rank_missing')
        if ('sig' not in msg.keys()):
            errors.append('sig_missing')
        if ('seq' not in msg.keys()):
            errors.append('seq_missing')
        if ('msg' in msg.keys() and msg['msg'] == 'rbrc'):
            if ('m' not in msg.keys()):
                errors.append('m_missing')
            else:
                if ('msg' not in msg['m'].keys()):
                    errors.append('m_msg_missing')
                else:
                    if (msg['m']['msg'] in MessageHandler.smpc_msgs):
                        if ('id' not in msg['m'].keys()):
                            errors.append('m_id_missing')
                        if ('index' not in msg['m'].keys()):
                            errors.append('m_index_missing')
        return errors

    @staticmethod
    def processRequest(msg_binary, state):
        return AbstractClassError()

    @staticmethod
    def encodeHeader(rank, seq, msg_type):
        return MessageHandler._msg.pack(
            VERSION,
            msg_type,
            rank,
            seq,
            0,
            chr(0x00) * (sig_length + 1)  # Leave signature empty, must be filled in later
        )

    @staticmethod
    def decodeHeader(msg):
        unpacked = MessageHandler._msg.unpack(msg[:header_length])
        return {  # Ignore version field
            'msg': MessageTypes.getString(unpacked[1]),
            'rank': unpacked[2],
            'seq': unpacked[3],
            'sig': unpacked[5]
        }

    @staticmethod
    def setRank(msg, rank):
        return msg[:2] + struct('>H').pack(rank) + msg[4:]

    @staticmethod
    def getRank(msg):
        return struct('>H').unpack(msg[2:4])[0]

    @staticmethod
    def setSequenceNumber(msg, seq):
        return msg[:4] + struct('>I').pack(seq) + msg[8:]

    @staticmethod
    def getSequenceNumber(msg):
        return struct('>I').unpack(msg[4:8])[0]

    @staticmethod
    def getMessageType(msg):
        return struct('>B').unpack(msg[1])[0]

    @staticmethod
    def createSessionErrors(state, errors):
        if ('rank_missing' in errors or 'sid_missing' in errors):
            return False  # Rank and SID are required to truly log errors...
        return True

    @staticmethod
    def setLength(msg):
        msg = msg[:8] + MessageHandler._msg_length.pack(len(msg)) + msg[12:]
        return msg

    @staticmethod
    def getLength(msg):
        return MessageHandler._msg_length.unpack(msg[8:12])[0]

    @staticmethod
    def signRequest(msg, crypter):
        sig = crypter.sign(msg)
        length = len(sig)
        sig = struct('>B').pack(len(sig)) + sig + (chr(0x00) * (sig_length - length))
        msg = msg[:12] + sig + msg[header_length:]
        return msg

    @staticmethod
    def checkSignature(msg, crypter):
        if (msg is None or crypter is None):
            return False
        length = struct('>B').unpack(msg[12])[0]
        sig = msg[13:(13 + length)]
        signstr = msg[:12] + (chr(0x00) * (sig_length + 1)) + msg[header_length:]
        result = crypter.verify(sig, signstr)
        return result

    @staticmethod
    def finalizeRequest(msg, crypter):
        msg = MessageHandler.setLength(msg)
        msg = MessageHandler.signRequest(msg, crypter)
        return msg

#####################################################################
#
#       HELO Message Handler
#
#####################################################################


class helo(MessageHandler):

    """ Structure of the helo message.
        Byte 1-16:   Session ID
        Bytes 17-51: Escrow address
        Bytes 52-55: Length of encrypted output address
        Bytes 56-oo: Encrypted output address """
    _msg = struct('>32s35sI')

    @staticmethod
    def encode(rank, seq, crypter, input_peer, encrypted_address):
        header = MessageHandler.encodeHeader(rank, seq, MessageTypes.HELO)
        payload = helo._msg.pack(
            input_peer['session_id'].decode('hex'),
            input_peer['address'],
            len(encrypted_address)
        )
        payload += encrypted_address
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result = MessageHandler.decodeHeader(msg[:header_length])
        unpacked = helo._msg.unpack(msg[header_length:(header_length + 71)])
        result.update({
            'sid': unpacked[0].encode('hex'),
            'escrow': unpacked[1],
            'output': msg[(header_length + 71):(header_length + 71 + unpacked[2])]
        })
        return result

    @staticmethod
    def processRequest(msg, state):
        log.debug('Received helo request.')
        errors = super(helo, helo).checkResponse(msg)
        if ('sid' not in msg.keys()):
            errors.append('sid_missing')
        if ('escrow' not in msg.keys()):
            errors.append('escrow_missing')
        if ('output' not in msg.keys()):
            errors.append('output_missing')
        if (len(errors) > 0):
            super(helo, helo).createSessionErrors(state, errors)
            response = ackn.encode(state.mixnet.getRank(), msg['seq'], state.crypto.getCrypter(), error=','.join(errors))
            return response
        escrow_address = msg['escrow'].strip(chr(0x00))
        log.debug('Flagging input peer with:\nrank=' + str(msg['rank']) + '\nescrow=' + str(escrow_address) + '\nsession_id=' + str(msg['sid']) + '\noutput_address=' + str(msg['output']))
        (result, error) = state.input.flagInputPeer(
            msg['rank'],
            escrow_address,
            msg['sid'],
            msg['output']
        )
        state.commit.increasePeerCount()
        state.commit.checkInputPeerThreshold()
        response = ackn.encode(state.mixnet.getRank(), msg['seq'], state.crypto.getCrypter(), error=error)
        return response

#####################################################################
#
#       ACKN Message Handler
#
#####################################################################


class ackn(MessageHandler):

    """ Structure of the ackn message.
        Byte 1:     Length of error message
        Bytes 2-oo: error message if NAK, else empty """
    _msg = struct('>B')

    @staticmethod
    def encode(rank, seq, crypter, error=None):
        header = MessageHandler.encodeHeader(rank, seq, MessageTypes.ACKN)
        payload = ackn._msg.pack(
            0x00 if error is None else len(error)
        )
        payload = payload if error is None else payload + error
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result = MessageHandler.decodeHeader(msg[:header_length])
        unpacked = ackn._msg.unpack(msg[header_length:(header_length + 1)])[0]
        error = msg[(header_length + 1):]
        result.update({'ack': ('true' if unpacked == 0x00 else 'false')})
        if (unpacked != 0x00):
            result.update({'reasons': error})
        return result

    @staticmethod
    def processRequest(msg, state):
        return RuntimeError('ACKN is only response, not request.')

#####################################################################
#
#       ADDR Message Handler @unused
#
#####################################################################


class addr(MessageHandler):

    """ Structure of the addr message.
        Byte 1-4:   Length of each list entry
        Bytes 5-6:  Number of list entries
        Bytes 6-oo: The array of addresses """
    _msg = struct('>H')
    _msg_addr = struct('>I')

    @staticmethod
    def encode(rank, seq, crypter, addresses):
        header = MessageHandler.encodeHeader(rank, seq, MessageTypes.ADDR)
        payload = addr._msg.pack(
            len(addresses)
        )
        payload += reduce(lambda x, y: x + y, map(lambda x: addr._msg_addr.pack(len(x)) + x, addresses))
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result = MessageHandler.decodeHeader(msg[:header_length])
        number_addresses = addr._msg.unpack(msg[header_length:(header_length + 2)])[0]
        outputs = []
        offset = header_length + 2
        for i in xrange(number_addresses):
            length = addr._msg_addr.unpack(msg[offset:(offset + 4)])[0]
            offset += 4
            outputs.append(msg[offset: (offset + length)])
            offset += length
        result.update({
            'outputs': outputs
        })
        return result

    @staticmethod
    def processRequest(msg, state):
        log.debug('Received addr request.')
        errors = super(addr, addr).checkResponse(msg)
        if ('outputs' not in msg.keys()):
            errors.append('outputs_missing')
        if (len(errors) > 0 or len(msg['outputs']) < state.input.getNumberInputPeers()):
            log.critical('addr error occurred, but I\'m not handling it.')
            return None
        state.shuffle.receivedAddrBroadcast(msg['outputs'], msg['rank'])


#####################################################################
#
#       General SMPC Message Handler
#
#####################################################################

class SmpcMessageHandler(MessageHandler):

    """ Structure of the smpc message header.
        Byte 1:     Algorithm of the SMPC value
        Bytes 2-5:  Index of the SMPC value
        Byte 6:     The length of the SMPC value identifier
        Bytes 7-oo: The identifier of the smpc value"""
    _msg = struct('>BIB')

    """ Identifiers for active SMPC values; WRAP, CMUL only use local computation, but are nevertheless assigned an ID here. """
    WRAP = 0x00  # Wrapper protocol
    CMUL = 0x01  # Constant multiplication
    REC = 0x02  # Recombination protocol
    MUL = 0x03  # Multiplication protocol
    DKG = 0x04  # Distributed Key Generation protocol
    JDKG = 0x05  # JfDkg for generation of H as needed for DKG

    @staticmethod
    def getAlgorithm(alg):
        if (alg == SmpcMessageHandler.JDKG):
            return 'jfdkg'
        elif (alg == SmpcMessageHandler.DKG):
            return 'dkg'
        elif (alg == SmpcMessageHandler.MUL):
            return 'mul'
        elif (alg == SmpcMessageHandler.REC):
            return 'rec'
        elif (alg == SmpcMessageHandler.WRAP):
            return 'wrap'
        elif (alg == SmpcMessageHandler.CMUL):
            return 'cmul'
        else:
            return RuntimeError('unknown smpc algorithm id')

    @staticmethod
    def getAlgorithmID(alg_str):
        if (alg_str == 'jfdkg'):
            return SmpcMessageHandler.JDKG
        elif (alg_str == 'dkg'):
            return SmpcMessageHandler.DKG
        elif (alg_str == 'mul'):
            return SmpcMessageHandler.MUL
        elif (alg_str == 'rec'):
            return SmpcMessageHandler.REC
        elif (alg_str == 'wrap'):
            return SmpcMessageHandler.WRAP
        elif (alg_str == 'cmul'):
            return SmpcMessageHandler.CMUL
        else:
            return RuntimeError('unknown smpc algorithm')

    @staticmethod
    def encodeHeader(rank, seq, crypter, msg_type, alg, id, index):
        header = MessageHandler.encodeHeader(rank, seq, msg_type)
        smpc_header = SmpcMessageHandler._msg.pack(
            SmpcMessageHandler.getAlgorithmID(alg),
            index,
            len(id),
        )
        smpc_header += id
        msg = header + smpc_header
        return msg

    @staticmethod
    def decodeHeader(msg):
        result = MessageHandler.decodeHeader(msg[:header_length])
        (alg, index, idlen) = SmpcMessageHandler._msg.unpack(msg[header_length:(header_length + 6)])
        offset = header_length + 6 + idlen
        id = msg[(header_length + 6):(offset)]
        result.update({
            'alg': SmpcMessageHandler.getAlgorithm(alg),
            'id': id,
            'index': index
        })
        return (result, offset)

    @staticmethod
    def checkResponse(msg, alg):
        errors = []
        if ('id' not in msg.keys()):
            errors.append('id_missing')
        if ('index' not in msg.keys()):
            errors.append('index_missing')
        if ('alg' not in msg.keys()):
            errors.append('alg_missing')
        if (alg != msg['alg']):
            errors.append('alg_mismatch')
        return errors

#####################################################################
#
#       MPCS Message Handler (SMPC Secret Values)
#
#####################################################################


class mpcs(SmpcMessageHandler):

    """ Structure of the mpcs message.
        Bytes 1-2:  Length of the secret value
        Bytes 3-oo: Secret value """
    _msg = struct('>H')

    @staticmethod
    def encode(rank, seq, crypter, alg, id, index, binary_secret_share):
        header = SmpcMessageHandler.encodeHeader(rank, seq, crypter, MessageTypes.MPCS, alg, id, index)
        payload = mpcs._msg.pack(
            len(binary_secret_share)
        )
        payload += binary_secret_share
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result, offset = SmpcMessageHandler.decodeHeader(msg)
        share_length = mpcs._msg.unpack(msg[offset:(offset + 2)])[0]
        binary_secret_share = msg[(offset + 2):(offset + 2 + share_length)]
        result.update({
            'share': binary_secret_share
        })
        return result

    @staticmethod
    def processRequest(msg, smpc_value):
        log.debug('Received mpcs request.')
        errors = super(mpcs, mpcs).checkResponse(msg, smpc_value.getAlgorithm())
        if ('share' not in msg.keys()):
            errors.append('share_missing')

        if (len(errors) > 0):
            log.error('Error receiving mpcs request. Error(s): ' + str(errors))
            return None

        try:
            if (len(errors) == 0):
                smpc_value.receivedSecretShare(msg['rank'], msg['share'])
        except BaseException:
            errors.append('share_internal_error')
            smpc_value.fireSecretDeferred(msg['rank'])

        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None
        else:
            log.debug('Received mpcs request (' + str(msg['id']) + ', ' + str(msg['index']) + ') from peer ' + str(msg['rank']) + '.')
        return None

#####################################################################
#
#       MPCP Message Handler (SMPC Public Value)
#
#####################################################################


class mpcp(SmpcMessageHandler):

    """ Structure of the mpcp message.
        Bytes 1-2:  Length of the public value
        Bytes 3-oo: Public value """
    _msg = struct('>H')

    @staticmethod
    def encode(rank, seq, crypter, alg, id, index, public_value):
        header = SmpcMessageHandler.encodeHeader(rank, seq, crypter, MessageTypes.MPCP, alg, id, index)
        payload = mpcp._msg.pack(
            len(public_value)
        )
        payload += public_value
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result, offset = SmpcMessageHandler.decodeHeader(msg)
        public_value_length = mpcp._msg.unpack(msg[offset:(offset + 2)])[0]
        public_value_bin = msg[(offset + 2):(offset + 2 + public_value_length)]
        result.update({
            'value': public_value_bin
        })
        return result

    @staticmethod
    def processRequest(msg, smpc_value):
        log.debug('Received mpcp request.')
        errors = super(mpcp, mpcp).checkResponse(msg, smpc_value.getAlgorithm())
        if ('value' not in msg.keys()):
            errors.append('value_missing')

        if (len(errors) > 0):
            log.error('Error receiving mpcp request. Error(s): ' + str(errors))
            return None

        try:
            if (len(errors) == 0):
                smpc_value.receivedPublicValue(msg['rank'], msg['value'])
        except BaseException:
            errors.append('value_internal_error')

        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None
        else:
            log.debug('Received mpcp request (' + str(msg['id']) + ', ' + str(msg['index']) + ') from peer ' + str(msg['rank']) + '.')
        return None

#####################################################################
#
#       COMP Message Handler (SMPC Complaint Message)
#
#####################################################################


class comp(SmpcMessageHandler):

    """ Structure of the comp message.
        Bytes 1-2:  Rank of the mixpeer being blamed
        Bytes 3-4:  Length of the optional parameter
        Bytes 5-oo: Optional parameter if previous field is > 0 """
    _msg = struct('>HH')

    @staticmethod
    def encode(rank, seq, crypter, alg, id, index, blamed_peer, opt=None):
        header = SmpcMessageHandler.encodeHeader(rank, seq, crypter, MessageTypes.COMP, alg, id, index)
        binary_opt = '{0:x}'.format(opt).decode('hex') if opt is not None else ''  # Compute binary presentation of opt
        payload = comp._msg.pack(
            blamed_peer,
            len(binary_opt)
        )
        payload += binary_opt
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result, offset = SmpcMessageHandler.decodeHeader(msg)
        blamed_peer, opt_length = comp._msg.unpack(msg[offset:(offset + 4)])
        opt_bin = msg[(offset + 4):(offset + 4 + opt_length)]
        result.update({
            'blame': blamed_peer
        })
        if opt_length > 0:
            result.update({
                'opt': int(opt_bin.encode('hex'), 16)
            })
        return result

    @staticmethod
    def processRequest(msg, smpc_value):
        log.debug('Received comp request.')
        errors = super(comp, comp).checkResponse(msg, smpc_value.getAlgorithm())
        if ('blame' not in msg.keys()):
            errors.append('blame_missing')
        opt = msg['opt'] if ('opt' in msg.keys()) else None
        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None

        smpc_value.receivedComplaint(msg['blame'], msg['rank'], opt)
        log.debug('Received comp request (' + str(msg['id']) + ', ' + str(msg['index']) + ') from peer ' + str(msg['rank']) + '.')
        return None

#####################################################################
#
#       CMPR Message Handler (SMPC Complaint Reaction Message)
#
#####################################################################


class cmpr(SmpcMessageHandler):

    """ Structure of the mpcs message.
        Bytes 1-2:  Rank of the mixpeer that blamed the reaction's sender
        Bytes 3-4:  Length of the justification value
        Bytes 5-oo: The justification value """
    _msg = struct('>HH')

    @staticmethod
    def encode(rank, seq, crypter, alg, id, index, blaming_peer, justification):
        header = SmpcMessageHandler.encodeHeader(rank, seq, crypter, MessageTypes.CMPR, alg, id, index)
        binary_justification = '{0:x}'.format(justification).decode('hex')  # Compute binary presentation of justification
        payload = cmpr._msg.pack(
            blaming_peer,
            len(binary_justification)
        )
        payload += binary_justification
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result, offset = SmpcMessageHandler.decodeHeader(msg)
        blaming_peer = cmpr._msg.unpack(msg[offset:(offset + 2)])
        justification_length = cmpr._msg.unpack(msg[(offset + 2):(offset + 4)])
        justification_bin = msg[(offset + 4):(offset + 4 + justification_length)]
        result.update({
            'blamer': blaming_peer,
            'value': justification_bin
        })
        return result

    @staticmethod
    def processRequest(msg, smpc_value):
        errors = super(cmpr, cmpr).checkResponse(msg, smpc_value.getAlgorithm())
        if ('blamer' not in msg.keys()):
            errors.append('blamer_missing')
        if ('value' not in msg.keys()):
            errors.append('value_missing')
        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None

        smpc_value.receivedComplaintReaction(msg['rank'], msg['blamer'], msg['value'])
        log.debug('Received cmpr request (' + str(msg['id']) + ', ' + str(msg['index']) + ') from peer ' + str(msg['rank']) + '.')
        return None

#####################################################################
#
#       NCMP Message Handler (SMPC "Nothing to Complain" Message)
#
#####################################################################


class ncmp(SmpcMessageHandler):

    @staticmethod
    def encode(rank, seq, crypter, alg, id, index):
        header = SmpcMessageHandler.encodeHeader(rank, seq, crypter, MessageTypes.NCMP, alg, id, index)
        msg = header
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result, _ = SmpcMessageHandler.decodeHeader(msg)
        return result

    @staticmethod
    def processRequest(msg, smpc_value):
        log.debug('Received ncmp request.')
        errors = super(ncmp, ncmp).checkResponse(msg, smpc_value.getAlgorithm())
        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None
        smpc_value.receivedComplaintNak(msg['rank'])
        log.debug('Received ncmp request (' + str(msg['id']) + ', ' + str(msg['index']) + ') from peer ' + str(msg['rank']) + '.')
        return None


#####################################################################
#
#       CBRC Message Handler (Consistent Broadcast)
#
#       TODO: Broadcast protocols cannot respond atm.
#
#####################################################################

class cbrc(MessageHandler):

    """ Structure of the broadcast message header.
        Bits 1-4: Type of broadcast used
        Bits 5-8: Type of the broadcast message """
    _msg = struct('>B')
    _msg_send = struct('>I')
    _msg_echo = struct('>B72s')
    _msg_finl = struct('>H')
    _msg_fsig = struct('>HB72s')

    """ Identifiers for the type of broadcast message. """
    SEND = 0x00  # Send message by sender
    ECHO = 0x01  # Echo message by receivers
    FINL = 0x02  # Final message by sender

    @staticmethod
    def getMessageTypeID(msg_type):
        if (msg_type == 's'):
            return cbrc.SEND
        elif (msg_type == 'e'):
            return cbrc.ECHO
        elif (msg_type == 'f'):
            return cbrc.FINL
        else:
            return RuntimeError('unknown consistent broadcast message type')

    @staticmethod
    def getMessageType(msg_type_id):
        if (msg_type_id == cbrc.SEND):
            return 's'
        elif (msg_type_id == cbrc.ECHO):
            return 'e'
        elif (msg_type_id == cbrc.FINL):
            return 'f'
        else:
            return RuntimeError('unknown consistent broadcast message type id')

    @staticmethod
    def encode(rank, seq, crypter, msg_type, value):
        header = MessageHandler.encodeHeader(rank, seq, MessageTypes.CBRC)

        payload = cbrc._msg.pack(
            msg_type
        )
        if (msg_type == cbrc.SEND):
            payload += cbrc._msg_send.pack(
                len(value)
            )
            payload += value
        elif (msg_type == cbrc.ECHO):
            payload += cbrc._msg_echo.pack(
                len(value),
                value + (chr(0x00) * (sig_length - len(value)))
            )
        elif (msg_type == cbrc.FINL):
            payload += cbrc._msg_finl.pack(
                len(value)
            )
            for i in xrange(len(value)):
                payload += cbrc._msg_fsig.pack(
                    value[i][0],
                    len(value[i][1]),
                    value[i][1] + (chr(0x00) * (sig_length - len(value[i][1])))
                )
        msg = header + payload
        return MessageHandler.finalizeRequest(msg, crypter)

    @staticmethod
    def decode(msg):
        result = MessageHandler.decodeHeader(msg)
        msg_type = cbrc._msg.unpack(msg[header_length:(header_length + 1)])[0]
        result.update({
            'type': cbrc.getMessageType(msg_type)
        })

        if (msg_type == cbrc.SEND):
            msg_length = cbrc._msg_send.unpack(msg[(header_length + 1):(header_length + 5)])[0]
            msg_encap = msg[(header_length + 5):(header_length + 5 + msg_length)]
            result.update({
                'm': msg_encap
            })
        elif (msg_type == cbrc.ECHO):
            length, sig = cbrc._msg_echo.unpack(msg[(header_length + 1):(header_length + 2 + sig_length)])
            sig = sig[:length]
            result.update({
                's': sig
            })
        elif (msg_type == cbrc.FINL):
            sig_num = cbrc._msg_finl.unpack(msg[(header_length + 1):(header_length + 3)])[0]
            signatures = []
            for i in xrange(sig_num):
                rank, length, sig = cbrc._msg_fsig.unpack(msg[(header_length + 3 + (i * (2 + 1 + sig_length))):(header_length + 3 + ((i + 1) * (2 + 1 + sig_length)))])
                sig = sig[:length]
                signatures += [[rank, sig]]
            result.update({
                's': signatures
            })
        return result

    @staticmethod
    def processRequest(msg, transaction, state):
        log.debug('Received cbrc request.')
        errors = super(cbrc, cbrc).checkResponse(msg)
        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None

        transaction.receivedResponse(msg)
        return None

#####################################################################
#
#       RBRC Message Handler (Reliable Broadcast)
#
#####################################################################

# FIXME: Finish refactoring reliable broadcast


class rbrc(MessageHandler):

    """ Structure of the broadcast message header.
        Bits 1-4: Type of broadcast used
        Bits 5-8: Type of the broadcast message """
    _msg = struct('>B')
    _msg_send = struct('>I')
    _msg_echo = struct('>72s')
    _msg_finl = struct('>H')
    _msg_fsig = struct('>H72s')

    """ Identifiers for the type of broadcast message. """
    SEND = 0x00  # Send message by sender
    ECHO = 0x01  # Echo message by receivers
    REDY = 0x02  # Ready message by receivers

    @staticmethod
    def getMessageType(msg_type):
        if (msg_type == 's'):
            return rbrc.SEND
        elif (msg_type == 'e'):
            return rbrc.ECHO
        elif (msg_type == 'r'):
            return rbrc.REDY
        else:
            return RuntimeError('unknown reliable broadcast message type')

    @staticmethod
    def getMessageTypeID(msg_type_id):
        if (msg_type_id == rbrc.SEND):
            return 's'
        elif (msg_type_id == rbrc.ECHO):
            return 'e'
        elif (msg_type_id == rbrc.REDY):
            return 'r'
        else:
            return RuntimeError('unknown reliable broadcast message type id')

    @staticmethod
    def encode(rank, seq, crypter, msg_type, value):

        # FIXME: Not refactored
        return NotImplementedError('Reliable broadcast not yet refactored')

        header = MessageHandler.encodeHeader(rank, seq, crypter, MessageTypes.CBRC)

        payload = cbrc._msg.pack(
            msg_type
        )
        if (msg_type == rbrc.SEND):
            payload += cbrc._msg_send.pack(
                len(value)
            )
            payload += value
        elif (msg_type == rbrc.ECHO):
            payload += cbrc._msg_echo.pack(
                value
            )
        elif (msg_type == rbrc.FINL):
            payload += cbrc._msg_finl.pack(
                len(value)
            )
            for i in xrange(len(value)):
                payload += cbrc._msg_fsig.pack(
                    value[0],
                    value[1]
                )
        msg = header + payload
        return MessageHandler.signRequest(msg, crypter)

    @staticmethod
    def decode(msg):

        # FIXME: Not refactored
        return NotImplementedError('Reliable broadcast not yet refactored')

        result = MessageHandler.decodeHeader(msg)
        msg_type = cbrc._msg.unpack(msg[header_length:(header_length + 1)])
        result.update({
            'type': cbrc.getMessageType(msg_type)
        })

        if (msg_type == rbrc.SEND):
            msg_length = cbrc._msg_send.unpack(msg[(header_length + 1):(header_length + 5)])
            msg_encap = msg[(header_length + 5):(header_length + 5 + msg_length)]
            result.update({
                'm': msg_encap
            })
        elif (msg_type == rbrc.ECHO):
            sig = cbrc._msg_echo.unpack(msg[(header_length + 1):(header_length + 73)])
            result.update({
                's': sig
            })
        elif (msg_type == rbrc.FINL):
            sig_num = cbrc._msg_finl.unpack(msg[(header_length + 1):(header_length + 3)])
            signatures = []
            for i in xrange(sig_num):
                rank, sig = cbrc._msg.fsig.unpack(msg[(header_length + 3 + (i * 74)):(header_length + 3 + ((i + 1) * 74))])
                signatures += [[rank, sig]]
            result.update({
                's': signatures
            })
        return result

    @staticmethod
    def processRequest(msg, state):

        # FIXME: Not refactored
        return NotImplementedError('Reliable broadcast not yet refactored')

        log.debug('Received cbrc request.')
        errors = super(cmpr, cmpr).checkResponse(msg)
        if (len(errors) > 0):
            log.error('Malformed message. Errors: ' + str(errors))
            log.error('Message was: ' + str(msg))
            return None

        transaction = state.transactions.findTransaction(msg['seq'])

        if (transaction is None):
            """ Ignore prematurely received final-messages.
                If final is received without first receiving send, the msg
                is unknown and also the sender is malicious. """
            if (not msg['type'] == 's'):
                return None
            msg_type = MessageHandler.getMessageType(msg['m'])
            request_handler = getMessageHandler(msg_type)
            transaction = ConsistentBroadcastTransaction(
                self.state.mixnet.getRank(),
                self.state.crypto.getCrypter(),
                self.state.mixnet.getConnectedMixpeers(),
                self.state.mixnet.getMixnetSize(),
                self.state.mixnet.getMixpeerThreshold(),
                msg['seq'],
                None,
                self.state.getP2pClientDeferred()
            )
            self.state.transactions.addTransaction(transaction)
            if (msg_type in MessageTypes.smpc_msgs):
                smpc_msg = request_handler.decode(msg['m'])
                smpc_value = state.smpc.getValue(smpc_msg['id'], smpc_msg['index'])
                if (smpc_value is None):
                    smpc_value = self.state.smpc.newValue(
                        smpc_msg['alg'],
                        state,
                        smpc_msg['id'],
                        smpc_msg['index']
                    )
                transaction.defineCallback(request_handler, smpc_value)
            else:
                transaction.defineCallback(request_handler, state)
        transaction.receivedResponse(msg)
        return None


#####################################################################
#
#       Message Handler / Types List
#
#####################################################################

__message_handlers = [helo, ackn, addr, mpcs, mpcp, comp, cmpr, ncmp, cbrc, rbrc]
__message_types = [MessageTypes.HELO, MessageTypes.ACKN, MessageTypes.ADDR,
                   MessageTypes.MPCS, MessageTypes.MPCP, MessageTypes.COMP,
                   MessageTypes.CMPR, MessageTypes.NCMP,
                   MessageTypes.CBRC, MessageTypes.RBRC]


def getMessageHandler(msg_type):
    try:
        return next((__message_handlers[i] for i in xrange(len(__message_handlers)) if __message_types[i] == msg_type))
    except:
        return None
