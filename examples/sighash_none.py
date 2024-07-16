from bsv import Unspent, Transaction, TransactionInput, PrivateKey
from bsv.constants import SIGHASH

private_key = PrivateKey('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
network = private_key.network
unspents = Unspent.get_unspents(network=network, private_keys=[private_key])

t = Transaction(network=network)
t.add_inputs([TransactionInput(unspent, sighash=SIGHASH.NONE_FORKID) for unspent in unspents])
t.sign()

# no outputs in tx now
assert len(t.outputs) == 0

# it's good to add any outputs here, no need to sign, can broadcast directly
t.add_change()
assert len(t.outputs) == 1
print(t.broadcast())
