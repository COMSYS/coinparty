.PHONY: check check2 clean
pyc=pychecker -F pycheckrc --debug
pyi=pyflakes
files= \
	mixing_peer/MixingPeer \
	mixing_peer/P2pEndpoints \
	mixing_peer/WebServer \
	mixing_peer/protocols/Transaction \
	mixing_peer/protocols/EscrowAddresses \
	mixing_peer/protocols/CommitmentProtocol \
	mixing_peer/protocols/ShufflingProtocol \
	mixing_peer/protocols/TransactionProtocol \
	mixing_peer/protocols/ErrorProtocol \
	mixing_peer/protocols/low/Bitcoin \
	mixing_peer/protocols/low/CoinPartyProxy \
	mixing_peer/protocols/low/ViffRuntime \
	mixing_peer/protocols/low/log \
	mixing_peer/protocols/low/TransactionStrategies \
	mixing_peer/protocols/state/BaseState \
	mixing_peer/protocols/state/InitialState \
	mixing_peer/protocols/state/CryptoState \
	mixing_peer/protocols/state/CommitmentState \
	mixing_peer/protocols/state/InputPeerState \
	mixing_peer/protocols/state/ShufflingState

check:
	mkdir -p logs/pyflakes
	for f in $(files); do \
		x=$$(echo $$f | grep -o -e "[a-zA-Zi0-9]*$$"); \
		$(pyi) $${f}.py > logs/pyflakes/$${x}.log 2>&1; \
	done
	cat $$(find logs/pyflakes/ -type f) > logs/result.log

clean:
	find . -name *.pyc | xargs rm -fv
