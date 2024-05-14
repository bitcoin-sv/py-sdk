from bsv.constants import Network
from bsv.keys import PrivateKey
from bsv.service.whatsonchain import WhatsOnChain
from bsv.wallet import Wallet


def test_chain_provider():
    w = Wallet()
    assert w.network == Network.MAINNET
    assert w.provider is None

    w = Wallet(network=Network.TESTNET)
    assert w.network == Network.TESTNET
    assert w.provider is None

    w = Wallet(provider=WhatsOnChain())
    assert w.network == Network.MAINNET
    assert isinstance(w.provider, WhatsOnChain)
    assert w.provider.network == Network.MAINNET

    w = Wallet(network=Network.TESTNET, provider=WhatsOnChain())
    assert w.network == Network.MAINNET
    assert isinstance(w.provider, WhatsOnChain)
    assert w.provider.network == Network.MAINNET


def test():
    p1 = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
    p2 = PrivateKey('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U')

    w1 = Wallet(provider=WhatsOnChain()).add_key(p1).add_key(p2)
    w2 = Wallet().add_keys([p1, p2])
    w3 = Wallet([p1, p2])

    assert w1.get_keys() == w2.get_keys()
    assert w1.get_keys() == w3.get_keys()

    assert w1.get_unspents() == []
    assert w1.get_balance() == 0

    w1.get_unspents(refresh=True)
    assert w1.get_balance() == w1.get_balance(refresh=True)

    w2.get_unspents(refresh=True)
    assert w2.get_balance() == w2.get_balance(refresh=True)

    assert w1.get_balance() == w2.get_balance()
