import time

from bsv import Wallet, TransactionOutput, Transaction, PrivateKey
from bsv.script import P2PK

k = PrivateKey('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
network = k.network

unspents = Wallet(network=network).add_keys([k, '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me']).get_unspents(refresh=True)
p2pk_output = TransactionOutput(P2PK.locking(k.public_key().serialize()), 996, P2PK())
t = Transaction(network=network).add_inputs(unspents).add_output(p2pk_output).add_change(k.address()).sign()
print('create p2pk:', t.broadcast())

time.sleep(2)
unspents = t.to_unspents(args=[{'private_keys': [k]}] * 2)
t = Transaction(network=network).add_inputs(unspents).add_change(k.address()).sign()
print('sepnd p2pk:', t.broadcast())
