import time
from typing import List, Union

from bsv import PrivateKey, Unspent, Transaction, TxOutput
from bsv.constants import Network
from bsv.script import BareMultisig, Script

network = Network.TESTNET
k1 = PrivateKey('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
k2 = PrivateKey('93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me')

# unspent of k1
unspents = Unspent.get_unspents(network=network, private_keys=[k1])

# a 2-of-3 multi-sig output
public_keys: List[Union[str, bytes]] = [k1.public_key().hex(), PrivateKey().public_key().hex(), k2.public_key().serialize()]
multisig_script: Script = BareMultisig.locking(public_keys, 2)
output = TxOutput(out=multisig_script, value=1000, script_template=BareMultisig())

# create multi-sig output
t = Transaction(network=network).add_inputs(unspents).add_output(output).add_change().sign()
r = t.broadcast()
print(f'create multisig - {r}')
assert r.propagated
time.sleep(2)

# send the multi-sig unspent we just created
unspent = t.to_unspent(0, private_keys=[k1, k2])
r = Transaction(network=network).add_input(unspent).add_change(k1.address()).sign().broadcast()
print(f'spend multisig - {r}')
