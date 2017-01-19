#!/usr/bin/env python

# Foo bar

from pyelliptic import ECC
from configobj import ConfigObj
from sys import argv, exit

if (len(argv) != 2):
    print('Error: No mixnet size given.\n\nUsage:\n{} mixnet_size'.format(argv[0]))
    exit(1)

CONFIG_FILENAME = 'mixnets.conf'

MIXNET_SIZE = int(argv[1])
BASE_PORT_WEB = 8000
BASE_PORT_P2P = 10000
MIXNET_NAME = 'sample_mixnet'

mixnet_config = {'global_config' : {'testnet' : 'True'}, 'mixing_peers' : {}, 'mixing_networks' : {MIXNET_NAME : {}}}

for mp in xrange(MIXNET_SIZE):
    mp_id = 'mp{0:02d}'.format(mp)
    mp_rank = mp
    mp_crypter = ECC(curve='secp256k1')
    mp_pubkey = mp_crypter.get_pubkey().encode('hex')
    mp_privkey = mp_crypter.get_privkey().encode('hex')

    mixnet_config['mixing_peers'][mp_id] = {'web_addr' : '{}.cp:{}'.format(mp_id, BASE_PORT_WEB + mp_rank), 'pubkey' : mp_pubkey, 'prvkey' : mp_privkey}
    mixnet_config['mixing_networks'][MIXNET_NAME][mp_id] = {'rank' : mp_rank, 'p2p_addr' : 'localhost:{}'.format(BASE_PORT_P2P + mp_rank)}

conf = ConfigObj()
for k in mixnet_config.keys():
    conf[k] = mixnet_config[k]

conf.filename = CONFIG_FILENAME
conf.write()
