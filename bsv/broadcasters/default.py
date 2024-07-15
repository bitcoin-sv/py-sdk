from ..broadcaster import Broadcaster
from .arc import ARC

def default_broadcaster() -> Broadcaster:
    return ARC('https://arc.taal.com')