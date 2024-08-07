from abc import ABC, abstractmethod

import aiohttp


class HttpClient(ABC):
    @abstractmethod
    def fetch(self, url: str, options: dict) -> "HttpResponse":
        pass


class HttpResponse:
    def __init__(self, ok: bool, status_code: int, json_data: dict):
        self.ok = ok
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


class DefaultHttpClient(HttpClient):
    async def fetch(self, url: str, options: dict) -> HttpResponse:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=options["method"],
                url=url,
                headers=options.get("headers", {}),
                json=options.get("data", None),
            ) as response:
                try:
                    json_data = await response.json()
                    return HttpResponse(
                        ok=response.status >= 200 and response.status <= 299,
                        status_code=response.status,
                        json_data={
                            'data': json_data
                        },
                    )
                except Exception as e:
                    return HttpResponse(
                        ok=False,
                        status_code=response.status,
                        json_data={},
                    )


def default_http_client() -> HttpClient:
    return DefaultHttpClient()
