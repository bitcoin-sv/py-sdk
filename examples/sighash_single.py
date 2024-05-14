from bsv import PrivateKey, Wallet, Transaction, TxInput, TxOutput
from bsv.constants import SIGHASH, Network
from bsv.service import WhatsOnChain

provider = WhatsOnChain(Network.TESTNET)
private_key = PrivateKey('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
unspents = Wallet([private_key]).get_unspents(refresh=True, provider=provider)

t = Transaction(provider=provider)
t.add_input(TxInput(unspents[0], sighash=SIGHASH.SINGLE_FORKID))
t.add_output(TxOutput(private_key.address(), 1))
t.sign()

# now tx has 1 output
assert len(t.outputs) == 1

# it's good to append any outputs AFTER the first output, no need to sign, can broadcast directly
t.add_change()
assert len(t.outputs) == 2
print(t.broadcast())
