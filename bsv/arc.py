import json
from typing import Union
from .transaction import Transaction
from .http_client import HttpClient, HttpResponse, default_http_client

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

class ARC:
    def __init__(self, URL: str, apiKey: str, httpClient: HttpClient = default_http_client()):

        self.URL = URL
        self.apiKey = apiKey
        self.httpClient = httpClient

    async def broadcast(self, tx: Transaction) -> Union[BroadcastResponse, BroadcastFailure]:

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
                return BroadcastResponse(txid=data['txid'],
                                         message=f"{data.get('txStatus', '')} {data.get('extraInfo', '')}")
            else:
                return BroadcastFailure(code=data.get('status', 'ERR_UNKNOWN'),
                                        description=data.get('detail', 'Unknown error'))
        except Exception as error:
            return BroadcastFailure(code='500',
                                    description=str(error) if isinstance(error, Exception) else 'Internal Server Error')
