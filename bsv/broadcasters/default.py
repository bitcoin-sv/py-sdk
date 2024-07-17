from .arc import ARC
from ..broadcaster import Broadcaster


def default_broadcaster() -> Broadcaster:
    return ARC('https://arc.taal.com')
