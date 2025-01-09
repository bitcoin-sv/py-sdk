import pytest
from bsv.broadcasters.whatsonchain import WhatsOnChainBroadcaster
from bsv.constants import Network
from bsv.broadcaster import BroadcastResponse, BroadcastFailure


class TestWhatsOnChainBroadcast:
    def test_network_enum(self):
        # Network enumでの初期化
        broadcaster = WhatsOnChainBroadcaster(Network.MAINNET)
        assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"

        broadcaster = WhatsOnChainBroadcaster(Network.TESTNET)
        assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/test/tx/raw"

    def test_network_string(self):
        # 文字列での初期化（後方互換性）
        broadcaster = WhatsOnChainBroadcaster("main")
        assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"

        broadcaster = WhatsOnChainBroadcaster("test")
        assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/test/tx/raw"

        broadcaster = WhatsOnChainBroadcaster("mainnet")
        assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"

        broadcaster = WhatsOnChainBroadcaster("testnet")
        assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/test/tx/raw"

    def test_invalid_network(self):
        # 無効なネットワーク文字列
        with pytest.raises(ValueError, match="Invalid network string:"):
            WhatsOnChainBroadcaster("invalid_network")