from typing import List, Optional

from .constants import Network
from .keys import PrivateKey
from .script.script import Script
from .script.type import ScriptType, P2PKH, Unknown
from .service.provider import Provider
from .service.service import Service


class Unspent:

    def __init__(self, **kwargs):
        """
        if the script type is P2PKH, then setting either one private key or an address is enough
        otherwise, then it is essential to set both locking script and script type
        """
        self.txid: str = kwargs.get('txid')
        self.vout: int = int(kwargs.get('vout'))
        self.value: int = int(kwargs.get('value'))
        self.height: int = -1 if kwargs.get('height') is None else kwargs.get('height')
        self.confirmations: int = 0 if kwargs.get('confirmations') is None else kwargs.get('confirmations')
        # check if passing private keys, P2PKH and P2PK only need one key, but other script types may need more
        self.private_keys: List[PrivateKey] = kwargs.get('private_keys') if kwargs.get('private_keys') else []
        # if address is not passed then try to parse it from the private key, otherwise check address only
        self.address: str = kwargs.get('address') or (self.private_keys[0].address() if self.private_keys else None)
        # address is good here when either address or private keys is passed
        # if script type is not set then check address, otherwise check script type only
        self.script_type: ScriptType = kwargs.get('script_type') or (P2PKH() if self.address else Unknown())
        # if locking script is not set then parse from address, otherwise check locking script only
        self.locking_script: Script = kwargs.get('locking_script') or (P2PKH.locking(self.address) if self.address else Script())

    def __str__(self) -> str:
        return f'<Unspent outpoint={self.txid}:{self.vout} value={self.value} address={self.address}>'

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Unspent):
            return self.txid == o.txid and self.vout == o.vout
        return super().__eq__(o)

    def __hash__(self) -> int:
        return f'{self.txid}:{self.vout}'.__hash__()

    @classmethod
    def get_unspents(cls,
                     network: Optional[Network] = None,
                     provider: Optional[Provider] = None,
                     **kwargs) -> List['Unspent']:
        unspents = Service(network, provider).get_unspents(**kwargs)
        return [Unspent(**unspent) for unspent in unspents]
