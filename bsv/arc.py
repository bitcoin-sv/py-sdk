import json
from typing import Union
from abc import ABC, abstractmethod

class BroadcastResponse:
    def __init__(self, txid: str, message: str):
        self.status = 'success'
        self.txid = txid
        self.message = message

class BroadcastFailure(Exception):
    def __init__(self, code: str, description: str):
        self.status = 'error'
        self.code = code
        self.description = description
        super().__init__(f"Broadcast failure ({code}): {description}")

class Transaction:
    def __init__(self, tx_data: str):
        self.tx_data = tx_data

    def to_hex_ef(self) -> str:
        # Implementation to convert transaction to hex EF format
        pass

    def to_hex(self) -> str:
        # Implementation to convert transaction to hex format
        pass

class HttpClient(ABC):
    @abstractmethod
    def fetch(self, url: str, options: dict) -> 'HttpResponse':
        pass

class HttpResponse:
    def __init__(self, ok: bool, status_code: int, json_data: dict):
        self.ok = ok
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data

def default_http_client() -> HttpClient:
    # Return an instance of a default HttpClient implementation
    pass

class ARC:
    def __init__(self, URL: str, apiKey: str, httpClient: HttpClient = default_http_client()):
        """
         instance of the ARC broadcaster.

        Args:
            URL (str).
            apiKey (str).
            httpClient (HttpClient).
        """
        self.URL = URL
        self.apiKey = apiKey
        self.httpClient = httpClient

    async def broadcast(self, tx: Transaction) -> Union[BroadcastResponse, BroadcastFailure]:
        """
        Broadcasts a transaction via ARC.

        Args:
            tx (Transaction).

        """
        try:
            rawTx = tx.to_hex_ef()
        except Exception as error:
            if str(error) == 'All inputs must have source transactions when serializing to EF format':
                rawTx = tx.to_hex()
            else:
                raise error

        request_options = {
            'method': 'POST',
            'headers': {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.apiKey}'
            },
            'body': json.dumps({'rawTx': rawTx})
        }

        try:
            response = await self.httpClient.fetch(f"{self.URL}/v1/tx", request_options)
            data = response.json()
            if data.get('txid') or response.ok or response.status_code == 200:
                return BroadcastResponse(txid=data['txid'], message=f"{data.get('txStatus', '')} {data.get('extraInfo', '')}")
            else:
                return BroadcastFailure(code=data.get('status', 'ERR_UNKNOWN'), description=data.get('detail', 'Unknown error'))
        except Exception as error:
            return BroadcastFailure(code='500', description=str(error) if isinstance(error, Exception) else 'Internal Server Error')
