from bsv import Wallet, Transaction, TxInput, PrivateKey
from bsv.constants import SIGHASH

private_key = PrivateKey('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
network = private_key.network
unspents = Wallet(keys=[private_key], network=network).get_unspents(refresh=True)

t = Transaction(network=network)
t.add_input(TxInput(unspents[0], sighash=SIGHASH.NONE_ANYONECANPAY_FORKID))
t.sign()

unlocking_script = t.inputs[0].unlocking_script.hex()

# it's good to add more inputs here
t.add_inputs(unspents[1:])
# function sign will ONLY sign inputs which unlocking script is empty
# because the first input was signed before, so it will NOT be re-signed this time
t.add_change().sign()

# ensure that we didn't re-sign the first input
assert t.inputs[0].unlocking_script.hex() == unlocking_script

print(t.broadcast())
