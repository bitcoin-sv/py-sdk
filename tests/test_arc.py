import unittest
from unittest.mock import AsyncMock, MagicMock

from bsv.broadcaster import BroadcastResponse, BroadcastFailure
from bsv.broadcasters.arc import ARC, ARCConfig
from bsv.http_client import HttpClient, HttpResponse
from bsv.transaction import Transaction


class TestARCBroadcast(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.URL = "https://api.taal.com/arc"
        self.api_key = "apikey_85678993923y454i4jhd803wsd02"
        self.tx = Transaction(tx_data="Hello sCrypt")

        # Mocking the Transaction methods
        self.tx.hex = MagicMock(return_value="hexFormat")

    async def test_broadcast_success(self):
        mock_response = HttpResponse(
            ok=True,
            status_code=200,
            json_data={
                "data": {
                    "txid": "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
                    "txStatus": "success",
                    "extraInfo": "extra",
                }
            },
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastResponse)
        self.assertEqual(
            result.txid,
            "8e60c4143879918ed03b8fc67b5ac33b8187daa3b46022ee2a9e1eb67e2e46ec",
        )
        self.assertEqual(result.message, "success extra")

    async def test_broadcast_failure(self):
        mock_response = HttpResponse(
            ok=False,
            status_code=400,
            json_data={
                "data": {"status": "ERR_BAD_REQUEST", "detail": "Invalid transaction"}
            },
        )
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(return_value=mock_response)

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "400")
        self.assertEqual(result.description, "Invalid transaction")

    async def test_broadcast_exception(self):
        mock_http_client = AsyncMock(HttpClient)
        mock_http_client.fetch = AsyncMock(side_effect=Exception("Internal Error"))

        arc_config = ARCConfig(api_key=self.api_key, http_client=mock_http_client)
        arc = ARC(self.URL, arc_config)
        result = await arc.broadcast(self.tx)

        self.assertIsInstance(result, BroadcastFailure)
        self.assertEqual(result.code, "500")
        self.assertEqual(result.description, "Internal Error")


if __name__ == "__main__":
    unittest.main()
