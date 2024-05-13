from typing import List, Dict, Optional

from .provider import Provider, BroadcastResult
from .whatsonchain import WhatsOnChain
from ..constants import Network


class Service:

    def __init__(self, network: Optional[Network] = None, provider: Optional[Provider] = None):
        if provider:
            self.provider = provider
        else:
            self.provider = WhatsOnChain(network or Network.MAINNET)
        self.network = self.provider.network

    def get_unspents(self, **kwargs) -> List[Dict]:
        return self.provider.get_unspents(**kwargs)

    def get_balance(self, **kwargs) -> int:
        return self.provider.get_balance(**kwargs)

    def broadcast(self, raw: str) -> BroadcastResult:
        return self.provider.broadcast(raw)
