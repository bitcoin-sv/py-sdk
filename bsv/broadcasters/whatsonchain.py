from typing import Union, TYPE_CHECKING

from ..broadcaster import Broadcaster, BroadcastFailure, BroadcastResponse
from ..http_client import HttpClient, default_http_client

if TYPE_CHECKING:
    from ..transaction import Transaction

class WhatsOnChainBroadcaster(Broadcaster):
    def __init__(self, network: str = "main", http_client: HttpClient = None):
        self.network = network
        self.URL = f"https://api.whatsonchain.com/v1/bsv/{network}/tx/raw"
        self.http_client = http_client if http_client else default_http_client()

    async def broadcast(
        self, tx: 'Transaction'
    ) -> Union[BroadcastResponse, BroadcastFailure]:
        request_options = {
            "method": "POST",
            "headers": {"Content-Type": "application/json", "Accept": "text/plain"},
            "data": {"txhex": tx.hex()},
        }

        try:
            response = await self.http_client.fetch(self.URL, request_options)
            if response.ok:
                txid = response.json()["data"]
                return BroadcastResponse(
                    status="success", txid=txid, message="broadcast successful"
                )
            else:
                return BroadcastFailure(
                    status="error",
                    code=str(response.status_code),
                    description=response.json()["data"],
                )
        except Exception as error:
            return BroadcastFailure(
                status="error",
                code="500",
                description=(str(error) if str(error) else "Internal Server Error"),
            )
