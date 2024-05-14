import time

from bsv import PrivateKey, Transaction, Unspent, TxOutput, TxInput
from bsv.script import Script


def create_then_spend(locking: Script, unlocking: Script):
    """
    create an unspent with the specific locking script, then spend it with the specific unlocking script
    """

    k = PrivateKey('cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA')
    network = k.network
    unspents = Unspent.get_unspents(network=network, private_keys=[k])

    t = Transaction(network=network).add_inputs(unspents).add_output(TxOutput(locking, 1000)).add_change(k.address()).sign()
    r = t.broadcast()
    print(f'create - {r}')
    assert r.propagated

    time.sleep(2)
    _input = TxInput(t.to_unspent(0), unlocking_script=unlocking)
    r = Transaction(network=network).add_input(_input).add_output(TxOutput(k.address(), 800)).broadcast()
    print(f'spend - {r}')
