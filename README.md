# CoinParty

## About

CoinParty [1, 2] is a protocol for the  _distributed_ mixing service for Bitcoin.
Bitcoin users mix their funds in order to maintain their financial privacy despite all of their everyday transactions being opaque on Bitcoin's blockchain.
Although the blockchain only records pseudonymous addresses, researchers found that de-anonymization is still possible (e.g., [3]).

Initially, centralized mixing services collected and randomly re-distributed the funds of privacy-aware users.
This way, each user becomes anonymous within the group of users participating in the same mixing operation.
The mixing service, however, can easily abort operation and steal its users' funds.

To overcome this, we designed and prototypically implemented CoinParty as a _distributed_ mixing service.
By using secure multiparty computation (SMC), we can distribute the intermediate control over bitoins to be mixed among multiple independent peers and thereby guarantee correct mixing even if up to (but excluding) one third of the peers are malicious.

In this repository, we publish a prototypic implementation of CoinParty.
However, the prototype is just a *proof-of-concept* implementation and *not suitable* for productive utilization!


[1]: J. H. Ziegeldorf, F. Grossmann, M. Henze, N. Inden, and K. Wehrle. CoinParty: Secure Multi-Party Mixing of Bitcoins. Proc. CODASPY'15. URL: https://www.comsys.rwth-aachen.de/fileadmin/papers/2015/2015-ziegeldorf-codaspy-coinparty.pdf
[2]: J. H. Ziegeldorf, R. Matzutt, M. Henze, F. Grossmann, and K. Wehrle. Secure and anonymous decentralized Bitcoin mixing. Future Generation Computer Systems. URL: http://www.sciencedirect.com/science/article/pii/S0167739X16301297.
[3]: F. Reid and M. Harrigan. An Analysis of Anonymity in the Bitcoin System. URL: https://arxiv.org/pdf/1107.4524.pdf.

## DISCLAIMER

This is just a *proof-of-concept* prototype and it is not suitable for production use.
The code is not sufficiently reviewed and probably insecure.
*DO NOT USE FOR MIXING BITCOINS.*
It is likely that your bitcoins will be lost!

The intention of releasing this code is to create a basis for the Bitcoin community to create a complete, reviewed, and robust implementation.

## Installation

This install guide is written for Ubuntu Linux.

* Get `git`, `python`, and `pip`:
```
sudo apt-get install git python python-pip libssl-dev
```

* Clone repository:
```
git clone git://github.com/comsys/coinparty.git
```

* Required dependencies:
```
pip install twisted ecdsa pycrypto python-bitcoinlib pyelliptic pyopenssl service_identity configobj
```

* Get `bitcoind`: https://bitcoin.org/en/download
* Get (and edit!) a `bitcoin.conf` file (Most importantly: enable and change RPC credentials and set `rpcport=8332`)
```
mkdir -p ~/.bitcoin
wget -O ~/.bitcoin/bitcoin.conf https://raw.githubusercontent.com/bitcoin/bitcoin/master/contrib/debian/examples/bitcoin.conf
```

* Create mixnet configuration file (in this example, of size 4):
```
python generate_mixnet_config.py 4
```

* Launch a mixnet (using `tmux`):
```
bash launch_mixnet.sh
```

* Close the mixnet by escaping from `tmux` via `C-b` and then typing:
```
tmux kill-session -t coinparty
```

Copyright (C) by 2016 Roman Matzutt, Henrik Ziegeldorf (Communication and Distributed Systems, RWTH Aachen University, Germany).
