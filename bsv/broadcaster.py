from typing import Union, Dict, Any
from abc import ABC, abstractmethod

#from .transaction import Transaction TODO: Fix recursive import


class BroadcastResponse:
    def __init__(self, status: str, txid: str, message: str):
        self.status = status
        self.txid = txid
        self.message = message


class BroadcastFailure:
    def __init__(
        self,
        status: str,
        code: str,
        description: str,
        txid: str = None,
        more: Dict[str, Any] = None,
    ):
        self.status = status
        self.code = code
        self.txid = txid
        self.description = description
        self.more = more


class Broadcaster(ABC):
    @abstractmethod
    async def broadcast(
        self, transaction: Any
    ) -> Union[BroadcastResponse, BroadcastFailure]:
        pass


def is_broadcast_response(r: Union[BroadcastResponse, BroadcastFailure]) -> bool:
    return r.status == "success"


def is_broadcast_failure(r: Union[BroadcastResponse, BroadcastFailure]) -> bool:
    return r.status == "error"

