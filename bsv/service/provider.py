from abc import ABCMeta, abstractmethod
from collections import namedtuple
from typing import List, Dict, Optional, Tuple, Union

import requests

from ..constants import Network, HTTP_REQUEST_TIMEOUT
from ..keys import PublicKey, PrivateKey

BroadcastResult = namedtuple('BroadcastResult', 'propagated data')


class Provider(metaclass=ABCMeta):

    def __init__(self,
                 network: Network = Network.MAINNET,
                 headers: Optional[Dict] = None,
                 timeout: Optional[int] = None):
        self.network: Network = network
        self.headers: Dict = headers or {'Content-Type': 'application/json', 'Accept': 'application/json', }
        self.timeout: int = timeout or HTTP_REQUEST_TIMEOUT

    def parse_kwargs(self, **kwargs) -> Tuple[Optional[str], Optional[PublicKey], Optional[PrivateKey]]:
        """
        try to parse out (address, public_key, private_key) from kwargs
        """
        private_key: PrivateKey = kwargs.get('private_keys')[0] if kwargs.get('private_keys') else None
        public_key: PublicKey = kwargs.get('public_key') or (private_key.public_key() if private_key else None)
        address: str = kwargs.get('address') or (public_key.address(network=self.network) if public_key else None)
        return address, public_key, private_key

    def get(self, **kwargs) -> Union[Dict, List[Dict]]:
        """
        HTTP GET wrapper
        """
        r = requests.get(
            kwargs['url'],
            headers=kwargs.get('headers') or self.headers,
            params=kwargs.get('params'),
            timeout=kwargs.get('timeout') or self.timeout
        )
        r.raise_for_status()
        return r.json()

    @abstractmethod
    def get_unspents(self, **kwargs) -> List[Dict]:
        raise NotImplementedError('Provider.get_unspents')

    @abstractmethod
    def get_balance(self, **kwargs) -> int:
        raise NotImplementedError('Provider.get_balance')

    @abstractmethod
    def broadcast(self, raw: str) -> BroadcastResult:
        raise NotImplementedError('Provider.broadcast')
