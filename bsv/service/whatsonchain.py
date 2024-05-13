import json
from typing import List, Dict, Optional

import requests

from .provider import Provider, BroadcastResult
from ..constants import Network


class WhatsOnChain(Provider):

    def __init__(self,
                 network: Network = Network.MAINNET,
                 headers: Optional[Dict] = None,
                 timeout: Optional[int] = None):
        super().__init__(network, headers, timeout)
        self.host: str = 'https://api.whatsonchain.com/v1/bsv'
        self._network = {
            Network.MAINNET: 'main',
            Network.TESTNET: 'test',
        }[network]

    def get_unspents(self, **kwargs) -> List[Dict]:
        try:
            address, _, _ = self.parse_kwargs(**kwargs)
            url = f'{self.host}/{self._network}/address/{address}/unspent'
            r: Dict = self.get(url=url)
            unspents: List[Dict] = []
            for item in r:
                unspent = {
                    'txid': item['tx_hash'],
                    'vout': item['tx_pos'],
                    'value': item['value'],
                    'height': item['height']
                }
                unspent.update(kwargs)
                unspents.append(unspent)
            return unspents
        except Exception as e:
            if kwargs.get('throw'):
                raise e
        return []

    def get_balance(self, **kwargs) -> int:
        try:
            address, _, _ = self.parse_kwargs(**kwargs)
            url = f'{self.host}/{self._network}/address/{address}/balance'
            r: Dict = self.get(url=url)
            return r.get('confirmed') + r.get('unconfirmed')
        except Exception as e:
            if kwargs.get('throw'):
                raise e
        return 0

    def broadcast(self, raw: str) -> BroadcastResult:
        propagated, message = False, ''
        try:
            data = json.dumps({'txHex': raw})
            url = f'{self.host}/{self._network}/tx/raw'
            r = requests.post(url=url, headers=self.headers, data=data, timeout=self.timeout)
            message = r.json()
            r.raise_for_status()
            propagated = True
        except Exception as e:
            message = message or str(e)
        return BroadcastResult(propagated, message)
