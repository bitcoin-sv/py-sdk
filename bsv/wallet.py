from concurrent.futures import ThreadPoolExecutor
from itertools import repeat
from typing import Optional, List, Tuple, Union, Dict, Any

from .constants import Network, THREAD_POOL_MAX_EXECUTORS
from .keys import PrivateKey
from .service.provider import Provider
from .service.service import Service
from .transaction import Transaction, TxOutput, InsufficientFunds
from .unspent import Unspent


def get_unspents_wrapper(network: Network, provider: Provider, d: Dict) -> List['Unspent']:
    return Unspent.get_unspents(network, provider, **d)


def get_balance_wrapper(network: Network, provider: Provider, d: Dict) -> int:
    return Service(network, provider).get_balance(**d)


class Wallet:
    def __init__(self,
                 keys: Optional[List[Union[str, int, bytes, PrivateKey]]] = None,
                 network: Optional[Network] = None,
                 provider: Optional[Provider] = None,
                 **kwargs):
        """
        create an empty wallet if keys is None
        """
        self.network: Network = network or Network.MAINNET
        self.provider: Provider = provider
        if self.provider:
            self.network = self.provider.network

        self.keys: List[PrivateKey] = []
        if keys:
            self.add_keys(keys)
        self.unspents: List[Unspent] = []
        self.kwargs: Dict[str, Any] = dict(**kwargs) or {}

    def add_key(self, key: Union[str, int, bytes, PrivateKey, None] = None) -> 'Wallet':
        """
        random a new private key then add to wallet if key is None
        """
        private_key = key if isinstance(key, PrivateKey) else PrivateKey(key)
        private_key.network = self.network
        self.keys.append(private_key)
        return self

    def add_keys(self, keys: List[Union[str, int, bytes, PrivateKey]]) -> 'Wallet':
        for key in keys:
            self.add_key(key)
        return self

    def get_keys(self) -> List[PrivateKey]:
        return self.keys

    def get_unspents(self, refresh: bool = False, **kwargs) -> List[Unspent]:
        if refresh:
            self.unspents = []
            network: Network = kwargs.pop('network', None) or self.network
            provider: Provider = kwargs.pop('provider', None) or self.provider
            with ThreadPoolExecutor(max_workers=THREAD_POOL_MAX_EXECUTORS) as executor:
                args = [dict(private_keys=[key], **{**self.kwargs, **kwargs}) for key in self.keys]
                for r in executor.map(get_unspents_wrapper, repeat(network), repeat(provider), args):
                    self.unspents.extend(r)
        return self.unspents

    def get_balance(self, refresh: bool = False, **kwargs) -> int:
        if refresh:
            network: Network = kwargs.pop('network', None) or self.network
            provider: Provider = kwargs.pop('provider', None) or self.provider
            with ThreadPoolExecutor(max_workers=THREAD_POOL_MAX_EXECUTORS) as executor:
                args = [dict(private_keys=[key], **{**self.kwargs, **kwargs}) for key in self.keys]
                return sum([r for r in executor.map(get_balance_wrapper, repeat(network), repeat(provider), args)])
        return sum([unspent.value for unspent in self.unspents])

    def create_transaction(self,
                           unspents: Optional[List[Unspent]] = None,
                           outputs: Optional[List[Tuple]] = None,
                           leftover: Optional[str] = None,
                           fee_rate: Optional[float] = None,
                           combine: bool = False,
                           pushdatas: Optional[List[Union[str, bytes]]] = None,
                           change: bool = True,
                           sign: bool = True,
                           **kwargs) -> Transaction:
        """create a transaction
        :param unspents: list of unspents, will refresh from service if None
        :param outputs: list of tuple (address, satoshi). if None then sweep all the unspents to leftover
        :param leftover: transaction change address
        :param fee_rate: default fee rate if None
        :param combine: use all available unspents if True
        :param pushdatas: list of OP_RETURN pushdata
        :param change: automatically add a P2PKH change output if True
        :param sign: sign the transaction if True
        :param kwargs: passing to get unspents and create transaction
        """
        unspents: List[Unspent] = unspents or self.get_unspents(refresh=True, **{**self.kwargs, **kwargs})
        return create_transaction(
            unspents=unspents,
            outputs=outputs,
            leftover=leftover,
            fee_rate=fee_rate,
            combine=combine,
            pushdatas=pushdatas,
            change=change,
            sign=sign,
            network=self.network,
            provider=self.provider,
            **{**self.kwargs, **kwargs}
        )


def create_transaction(unspents: List[Unspent],
                       outputs: Optional[List[Tuple]] = None,
                       leftover: Optional[str] = None,
                       fee_rate: Optional[float] = None,
                       combine: bool = False,
                       pushdatas: Optional[List[Union[str, bytes]]] = None,
                       change: bool = True,
                       sign: bool = True,
                       network: Optional[Network] = None,
                       provider: Optional[Provider] = None,
                       **kwargs) -> Transaction:
    """create a transaction
    :param unspents: list of unspents, will refresh from service if None
    :param outputs: list of tuple (address, satoshi). if None then sweep all the unspents to leftover
    :param leftover: transaction change address
    :param fee_rate: default fee rate if None
    :param combine: use all available unspents if True
    :param pushdatas: list of OP_RETURN pushdata
    :param change: automatically add a P2PKH change output if True
    :param sign: sign the transaction if True
    :param network: chain network
    :param provider: service provider
    :param kwargs: passing to get unspents and create transaction
    """
    if not unspents:
        raise InsufficientFunds('transaction mush have at least one unspent')
    t = Transaction(fee_rate=fee_rate, network=network, provider=provider, **kwargs)
    if pushdatas:
        t.add_output(TxOutput(pushdatas))
    if outputs:
        t.add_outputs([TxOutput(output[0], output[1]) for output in outputs])
    # pick unspent
    picked_unspents: List[Unspent] = []
    while unspents and (combine or not outputs or t.fee() < t.estimated_fee()):
        unspent = unspents.pop()
        picked_unspents.append(unspent)
        t.add_input(unspent)
    if t.fee() < t.estimated_fee():
        unspents.extend(picked_unspents)
        raise InsufficientFunds(f'require {t.estimated_fee() + t.total_value_out()} satoshi but only {t.total_value_in()}')
    if change:
        t.add_change(leftover)
    if sign:
        t.sign()
    return t
