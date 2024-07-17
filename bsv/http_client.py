from abc import ABC, abstractmethod

import aiohttp


class HttpClient(ABC):
    @abstractmethod
    async def fetch(self, url: str, options: dict) -> 'HttpResponse':
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
                    method=options['method'],
                    url=url,
                    headers=options.get('headers', {}),
                    data=options.get('body', None)
            ) as response:
                json_data = await response.json()
                return HttpResponse(ok=response.status == 200, status_code=response.status, json_data=json_data)


def default_http_client() -> HttpClient:
    return DefaultHttpClient()
