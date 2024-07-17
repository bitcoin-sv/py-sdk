from .whatsonchain import WhatsOnChainTracker
from ..chaintracker import ChainTracker


def default_chain_tracker() -> ChainTracker:
    return WhatsOnChainTracker()
