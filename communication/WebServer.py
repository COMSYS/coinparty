""" CoinParty - Web Endpoint
    A twisted-based custom server providing the user frontend of CoinParty.
    It delivers HTML files that are augmented by variable placeholders
    filled in by values of local variables. If necessary, other backend
    messages are triggered.

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

from twisted.web import resource
from twisted.web import server
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.web.server import NOT_DONE_YET

import re
from decimal import Decimal

from protocols.state.BaseState import mstate

from protocols.low.log import Logger, DeferredLogger
log = Logger('webserver')


# Only place files here that are uncritical for mixing operation and cannot trigger any action in the protocols
allowedFiles = [
    'style.css',
    'favicon.ico',
    'logo.png',
    'bitcore.js',
    'biginteger.js',
    'coinparty.js'
]


def createWebServer(port):
    webserver = WebServer(port)
    deferred = webserver.start()
    return (webserver, deferred)


class WebServer():
    def __init__(self, port):
        self.connection = None
        self.port = port

    def start(self):
        def _debug_working(_):
            log.debug('Web server is up and ready.')
        deferred = Deferred()
        deferred.addCallback(_debug_working)
        # FIXME: This connection MUST be TLS-secured
        self.connection = reactor.listenTCP(self.port, server.Site(rootPage()))
        # self.connection = reactor.listenSSL(web_port, site, ssl.DefaultOpenSSLContextFactory("./privatekey.pem", "./cacert.pem"))
        deferred.callback(None)
        return deferred

    def shutdown(self):
        try:
            d = self.connection.stopListening()
            d.addCallback(DeferredLogger.info, msg='Web server was shut down.')
        except AttributeError:
            d = Deferred()
            d.addCallback(DeferredLogger.info, msg='Web server did not have to be shut down.')
            d.callback(None)
        return d


def getSessionData(pageobj, input_peer, content):

    def _get_phase():
        """ Different phases in the protocol flow:
            N (phase 1) - New input peer
                          The user has sent his encrypted output address and
                          hash share
            E (phase 2) - Escrow transaction
                          The mixnet is waiting for the escrow transaction to
                          be confirmed
            W (phase 3) - Waiting for participants
                          The escrow transaction has been confirmed, but the
                          commitment window is still open.
            I (phase 4) - Initialization (the mixing)
                          Mixnet is currently mixing the output addresses or
                          preparing streaming parameters.
            S (phase 5) - Streaming
                          Everything has been agreed on. The mixnet is
                          transferring the funds from escrow addresses to the
                          output addresses.
            H (phase 6) - Halted
                          Each transaction has been concluded. """
        if (input_peer['txid'] is not None):
            return 1
        if (not input_peer['tx_confirmed']):
            return 2
        if (not pageobj.state.allPaymentsReceived()):
            return 3
        if (not (pageobj.state.isInStreamingPhase() or pageobj.state.isMixingConcluded())):
            return 4
        if (not pageobj.state.isMixingConcluded()):
            return 5
        else:
            return 6

    def _get_phase_string(phase):
        if (phase == 0):
                phase_str = '<p><b>Null</b></p><p class="text">' \
                    'You didn\'t do anything yet.</p>'
        elif (phase == 1):
            phase_str = '<p><b><u>N</u>ew Input Peer</b></p><p class="text">' \
                'You have registered as an input peer to this ' \
                'mixing operation. However, the mixnet did not yet see your Bitcoin commitment yet. ' \
                'Please submit your Bitcoins to the mixnet by performing the transaction indicated below.</p>'
        elif (phase == 2):
            phase_str = '<p><b><u>E</u>scrow Transaction Confirmation</b></p><p class="text">' \
                'The mixnet is waiting for your commitment to be confirmed.</p>'
        elif (phase == 3):
            phase_str = '<p><b><u>W</u>aiting</b></p><p class="text">' \
                'You successfully commited to the mixing operation. ' \
                'Right now, the mixnet is waiting for additional participants to join the operation. ' \
                'Either, the minimum time as specified by the commitment window has not yet passed, ' \
                'or the minimum number of input peers has not yet been reached. ' \
                'For further details, refer to the detailed report below.</p>'
        elif (phase == 4):
            phase_str = '<p><b><u>I</u>nitializing</b></p><p class="text">' \
                'The mixnet is about to start the mixing, but has yet to prepare the required parameters.</p>'
        elif (phase == 5):
            phase_str = '<p><b><u>S</u>treaming of Bitcoins</b></p><p class="text">' \
                'The Bitcoins are being mixed right now! ' \
                'You should watch your wallet for incoming transactions.</p>'
        elif (phase == 6):
            phase_str = '<p><b><u>H</u>alting Point Reached</b></p><p class="text">' \
                'Everything is over! By now, you should have received the same amount of Bitcoins that ' \
                'you initially commited. Check your wallet! However, it is possible that not all mixing ' \
                'transactions have been confirmed yet.</p>'
        return phase_str

    reports_empty = '<ul>\n' + ('\t<li>loading</li>\n' * pageobj.state.mixnet.getMixnetSize()) + '</ul>\n'

    phase = _get_phase()
    phase_str = _get_phase_string(phase)
    remaining_time = pageobj.state.commit.getRemainingTime()

    """
    if (remaining_time > 0):
        time_string = 'Mixing starting in <span id="time"></span>.' \
            if pageobj.state.commit.minInputPeerThresholdReached() \
            else 'Mixing starting not earlier than in <span id="time"></span>. Waiting for at least ' \
                + str(pageobj.state.commit.getMinimumNumberInputPeers()) \
                + ' input peers.'
    else:
        time_string = 'Mixing will start once the minimum number of ' \
            + str(pageobj.state.commit.getMinimumNumberInputPeers()) \
            + ' input peers has been reached.'
    """
    time_string = ''  # ToDo: Deprecated? (unless Henrik wants this)

    pageobj.replacements.update({
        '\#cp\_sid\#'      : str(input_peer['session_id']),
        '\#cp\_escrow\#'   : str(input_peer['address']),
        '\#cp\_value\#'    : str(pageobj.state.getBitcoinValue() + pageobj.state.getTransactionFee()),
        '\#cp\_feeless\#'  : str(pageobj.state.getBitcoinValue()),
        '\#cp\_report\#'   : reports_empty,
        '\#cp\_timestr\#'  : time_string,
        '\#cp\_phase\#'    : str(phase),
        '\#cp\_phasestr\#' : phase_str,
        '\#cp\_pin\#'      : str(input_peer['used_secret'])
    })
    content = pageobj.replacePlaceholders(content)
    pageobj.replacements.update({
        '\#cp\_time\#'    : str(remaining_time)
    })
    content = pageobj.replacePlaceholders(content)
    return content


class htmlParser(resource.Resource):
    isLeaf = True

    def __init__(self, path):
        resource.Resource.__init__(self)
        self.path = re.sub('(\.\./)*', '', path)  # Explicitly disallow access to "../" (maybe implicitly done by twisted)
        self.replacements = {
            '\#cp\_id\#'   : mstate.getMixpeerID(),
            '\#cp\_host\#' : 'coinparty.org'
        }

    def replacePlaceholders(self, content):
        # Based on http://stackoverflow.com/a/6117124/1643459
        dict((re.escape(k), v) for k, v in self.replacements.iteritems())
        self.replacer = re.compile("|".join(self.replacements.keys()))
        html = self.replacer.sub(lambda m: self.replacements[re.escape(m.group(0))], content)
        return html

    def error_parse(self, error='Unknown error'):
        self.replacements.update({
            '\#cp\_error\#' : '<p>' + error + '</p>\n\n'
        })
        return self.parse()

    def parse(self):
        try:
            with open('www/' + self.path, 'r') as res:
                content = res.read()
        except:
            with open('www/error.html', 'r') as res:
                content = res.read()

        return self.replacePlaceholders(content)

    def render_GET(self, request):
        return self.parse()


class htmlError(htmlParser):
    def __init__(self, error):
        htmlParser.__init__(self, 'error.html')
        self.replacements.update({
            '\#cp\_error\#' : '<p>' + error + '</p>\n\n'
        })


class indexPage(htmlParser):
    def __init__(self):
        htmlParser.__init__(self, 'index.html')

    def render_GET(self, request):
        list = '<ul>\n'
        list += mstate.getFormattedMixnetList(
            '\t<li><a href="/mix/#id#">#id#</a></li>\n',
            '\t<li><span style="color:#A8A8A8">#id#</span></li>\n'
        )
        list += '</ul>\n'
        self.replacements.update({'\#cp\_mixnets\#' : list})

        if (request.cookies is not None and len(request.cookies) > 0):
            verify_list = '<ul>\n'
            verify_list += mstate.getFormattedVerifyList(
                '\t<li><a href="/verify/' + session_id + '">#id#</a> (Verify)</li>\n',
                request.cookies
            )
            verify_list += '</ul>\n'
        else:
            verify_list = ''
        self.replacements.update({'\#cp\_verifylist\#' : verify_list})
        return self.parse()


class apiHandler(resource.Resource):
    isLeaf = True

    def setCors(self, request, state):
        origin = request.getHeader('Origin')
        if (origin in [state.mixnet.getMixpeers()[i]['web'] for i in xrange(0, state.mixnet.getMixnetSize())]):
            request.setHeader('Access-Control-Allow-Origin', origin)

    def render_GET(self, request):

        def finishVerification(v, request, input_peer, escrow, input_value, value):
            valid = (input_peer['address'] == escrow and Decimal(input_value) == value)
            secret = input_peer['used_secret']
            request.write('{"ack":"' + ("true" if valid else "false") + '","pin":"' + secret + '"}')
            request.finish()
            return v

        msg_type = request.args['msg'][0]
        if (msg_type == 'hmac'):
            # FIXME: prevent DoS, check for hash value
            state = mstate.getState(request.args['mixnet'][0])
            state.commit.addPendingNonce(request.args['hmac'][0])
            self.setCors(request, state)
            return '{"ack":"true"}'
        elif (msg_type == 'share'):
            """ Extract secret share. """
            state = mstate.getState(request.args['mixnet'][0])
            self.setCors(request, state)
            hash_share = map(lambda x: int(x), request.args['share'][0].split(','))
            session_id = request.args['sid'][0]
            secret = request.args['secret'][0]
            nonce = request.args['nonce'][0]

            if (state.commit.checkPendingNonce(secret, nonce)):
                try:
                    input_peer = state.input.getInputPeer('session_id', session_id)
                    log.debug('Found input peer with ID ' + str(input_peer['id']))
                    input_peer['used_secret'] = secret
                    input_peer['secret_deferred'].callback(secret)
                except:
                    log.critical('Did not find input peer for session ID ' + str(session_id))
                    print('Session IDs: ' + str(map(lambda x: x['session_id'], state.input._escrow_addresses)))
                    return '{"ack":"false"}'
                input_peer['hash_share'].callback(hash_share)
                return '{"ack":"true"}'
            else:
                log.critical('Incorrect nonce for session ' + str(session_id))
                return '{"ack":"false"}'
        elif (msg_type == 'verify'):
            try:
                session_id = request.args['sid'][0]
                escrow = request.args['escrow'][0]
                value = request.args['value'][0]
            except:
                log.critical('Missing parameters. Ignoring request.')
                return '{"ack":"false"}'
            try:
                st = mstate.findInputPeer(session_id)
                input_peer = st['input_peer']
                state = st['state']
                self.setCors(request, state)
            except:
                log.critical('Did not find input peer for session ID ' + str(session_id))
                return '{"ack":"false"}'

            d = input_peer['secret_deferred']
            d.addCallback(finishVerification, request, input_peer, escrow, value, state.getBitcoinValue())
            return NOT_DONE_YET
        else:
            log.critical('Invalid message type for session ' + str(session_id))
            return '{"ack":"false"}'

    def render_POST(self, request):
        return '{"error":"forbidden"}'


class rootApiPage(resource.Resource):
    isLeaf = False

    def __init__(self):
        resource.Resource.__init__(self)

    def getChild(self, path, request):
        if (path != ''):
            return '{error:"bogus request path"}'
        return apiHandler()

    def render(self, request):
        return '{error:"forbidden"}'


class initiateMixing(htmlParser):
    isLeaf = True

    def __init__(self, mixnet_id):
        htmlParser.__init__(self, 'mixing.html')
        self.mixnet_id = mixnet_id
        self.state = mstate.getState(mixnet_id)
        self.replacements.update({'\#cp\_mixnet\#' : self.mixnet_id})

    def render_response(self, input_peer):
        try:
            # FIXME: Block web server for late registration requests, but don't block response of last peer...
            #if (self.state.webServerBlocked() and self.state.input.inputPeersFrozen()):
            #    raise RuntimeError('webserver_blocked')
            with open('www/' + self.path, 'r') as res:
                content = res.read()
        except:
            self.path = 'error.html'
            self.error_parse('File not found.')

        content = getSessionData(self, input_peer, content)

        self.request.addCookie(self.state.mixnet.getMixnetID(), str(input_peer['session_id']), max_age=7200, path='/')
        self.request.write(content)
        self.request.finish()
        return

    def render_GET(self, request):
        """ Display the mixing form. """

        if (self.state is None):
            self.path = 'error.html'
            return self.error_parse('Mixnet "' + self.mixnet_id + '" is unknown.')

        if (self.state.webServerBlocked()):
            self.path = 'error.html'
            return self.error_parse('Mixnet is busy.')

        pubkeys_js = '[\n'
        for peer in self.state.mixnet.getMixpeers():
            pubkeys_js += '\t\t\t\t\"' + ('' if peer['pub'] is None else peer['pub']) + '\",\n'
        pubkeys_js += '\t\t\t]'
        self.replacements.update({'\#cp\_pubkeys\#' : pubkeys_js})

        addresses_js = '[\n'
        for peer in self.state.mixnet.getMixpeers():
            peerstr = '["' + ('' if peer['web'] is None else peer['web']) + '","' + ('' if peer['id'] is None else peer['id']) + '"]'
            addresses_js += '\t\t\t\t' + peerstr + ',\n'
        addresses_js += '\t\t\t]'
        self.replacements.update({'\#cp\_peeraddrs\#' : addresses_js})
        return self.parse()

    def render_POST(self, request):
        """ Process form content and start commitment protocol for one input peer. """

        # TODO: Verify form data. In case of error, fallback to displaying form.

        self.path = 'transact.html'

        addresses_js = '[\n'
        for peer in self.state.mixnet.getMixpeers():
            peerstr = '["' + ('' if peer['web'] is None else peer['web']) + '","' + ('' if peer['id'] is None else peer['id']) + '"]'
            addresses_js += '\t\t\t\t' + peerstr + ',\n'
        addresses_js += '\t\t\t]'
        self.replacements.update({
            '\#cp\_peeraddrs\#' : addresses_js,
            '\#cp\_mixnet\#' : self.state.mixnet.getMixnetID(),
            '\#cp\_n\#' : str(self.state.mixnet.getMixnetSize()),
            '\#cp\_t\#' : str(self.state.mixnet.getMixpeerThreshold())
        })

        self.request = request
        d = self.state.getP2pClient().request_helo(request.args['output'][0].decode('hex'))
        d.addCallback(self.render_response)
        return NOT_DONE_YET


class rootMixingPage(resource.Resource):
    isLeaf = False

    def __init__(self):
        resource.Resource.__init__(self)

    def getChild(self, path, request):
        if (path == ''):
            return htmlError('File not found.')
        return initiateMixing(path)

    def render(self, request):
        return htmlError('Forbidden').parse()


class verifyPage(htmlParser):
    isLeaf = True

    def __init__(self):
        htmlParser.__init__(self, 'verify.html')

    def render_response(self, _, request):

        try:
            with open('www/' + self.path, 'r') as res:
                content = res.read()
        except:
            self.path = 'error.html'
            return self.parse()

        content = getSessionData(self, self.input_peer, content)
        addresses_js = '[\n'
        for peer in self.state.mixnet.getMixpeers():
            peerstr = '["' + ('' if peer['web'] is None else peer['web']) + '","' + ('' if peer['id'] is None else peer['id']) + '"]'
            addresses_js += '\t\t\t\t' + peerstr + ',\n'
        addresses_js += '\t\t\t]'
        self.replacements.update({
            '\#cp\_peeraddrs\#' : addresses_js
        })
        content = self.replacePlaceholders(content)

        request.write(content.encode('utf-8'))
        request.finish()
        return

    def render(self, request):
        try:
            sid = request.args['sid'][0]  # got sid per GET?
        except:
            sid = None
        if (sid is None):
            self.path = 'verify_no_sid.html'
            self.replacements.update({
                '\#cp\_error\#' : ''
            })
            return self.parse()

        mn_ip = mstate.findInputPeer(sid)
        if (mn_ip is None or mn_ip['input_peer'] is None):
            self.path = 'verify_no_sid.html'
            self.replacements.update({
                '\#cp\_error\#' : '<p class="text"><span class="error">Error! Session ID not found.</span></p>\n\n'
            })
            return self.parse()

        self.input_peer = mn_ip['input_peer']
        self.state = mn_ip['state']

        # Print verify information
        d = self.input_peer['secret_deferred']
        d.addCallback(self.render_response, request=request)
        return NOT_DONE_YET

    def render_POST(self, request):
        try:
            received_session_id = request.args['sid'][0]
        except:
            return self.render_GET(request, True)
        return self.render_GET(request, False, session_id=received_session_id)


class rootPage(resource.Resource):
    isLeaf = False

    def __init__(self):
        resource.Resource.__init__(self)

    def getChild(self, path, request):
        if (path in allowedFiles):
            pass
        elif (path.startswith('mix')):
            return rootMixingPage()
        elif (path.startswith('api')):
            return rootApiPage()
        elif (path == 'verify'):
            return verifyPage()
        elif (path == ''):
            return indexPage()
        else:
            path = 'error.html'

        return htmlParser(path)
