import json
import random
from typing import Optional, Dict, Union, TYPE_CHECKING

from ..broadcaster import BroadcastResponse, BroadcastFailure, Broadcaster
from ..http_client import HttpClient, default_http_client


if TYPE_CHECKING:
    from ..transaction import Transaction

def to_hex(bytes_data):
    return "".join(f"{x:02x}" for x in bytes_data)


def random_hex(length: int) -> str:
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(length))


class ARCConfig:
    def __init__(
        self,
        api_key: Optional[str] = None,
        http_client: Optional[HttpClient] = None,
        deployment_id: Optional[str] = None,
        callback_url: Optional[str] = None,
        callback_token: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.api_key = api_key
        self.http_client = http_client
        self.deployment_id = deployment_id
        self.callback_url = callback_url
        self.callback_token = callback_token
        self.headers = headers


def default_deployment_id() -> str:
    return f"py-sdk-{random_hex(16)}"


class ARC(Broadcaster):
    def __init__(self, url: str, config: Union[str, ARCConfig] = None):
        self.URL = url
        if isinstance(config, str):
            self.api_key = config
            self.http_client = default_http_client()
            self.deployment_id = default_deployment_id()
            self.callback_url = None
            self.callback_token = None
            self.headers = None
        else:
            config = config or ARCConfig()
            self.api_key = config.api_key
            self.http_client = config.http_client or default_http_client()
            self.deployment_id = config.deployment_id or default_deployment_id()
            self.callback_url = config.callback_url
            self.callback_token = config.callback_token
            self.headers = config.headers

    async def broadcast(
        self, tx: 'Transaction'
    ) -> Union[BroadcastResponse, BroadcastFailure]:
        request_options = {
            "method": "POST",
            "headers": self.request_headers(),
            "data": {"rawTx": tx.to_ef().hex()},
        }

        try:
            response = await self.http_client.fetch(
                f"{self.URL}/v1/tx", request_options
            )
            
            response_json = response.json()
            
            if response.ok and response.status_code >= 200 and response.status_code <= 299:
                data = response_json["data"]

                if data.get("txid"):
                    return BroadcastResponse(
                        status="success",
                        txid=data.get("txid"),
                        message=f"{data.get('txStatus', '')} {data.get('extraInfo', '')}",
                    )
                else:
                    return BroadcastFailure(
                        status="failure",
                        code=data.get("status", "ERR_UNKNOWN"),
                        description=data.get("detail", "Unknown error"),
                    )
            else:
                return BroadcastFailure(
                    status="failure",
                    code=str(response.status_code),
                    description=response_json["data"]["detail"] if "data" in response_json else "Unknown error",
                )
            
        except Exception as error:
            return BroadcastFailure(
                status="failure",
                code="500",
                description=(
                    str(error)
                    if isinstance(error, Exception)
                    else "Internal Server Error"
                ),
            )

    def request_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "XDeployment-ID": self.deployment_id,
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        if self.callback_url:
            headers["X-CallbackUrl"] = self.callback_url

        if self.callback_token:
            headers["X-CallbackToken"] = self.callback_token

        if self.headers:
            headers.update(self.headers)

        return headers
