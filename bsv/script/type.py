from abc import abstractmethod, ABCMeta
from typing import Union, List

from .script import Script
from ..constants import OpCode, PUBLIC_KEY_HASH_BYTE_LENGTH, SIGHASH, PUBLIC_KEY_BYTE_LENGTH_LIST
from ..utils import address_to_public_key_hash, encode_pushdata, encode_int


class ScriptType(metaclass=ABCMeta):
    """
    script type demonstration in singleton
    """
    __instances = {}

    def __new__(cls, *args, **kwargs):
        if cls not in cls.__instances:
            cls.__instances[cls] = super(ScriptType, cls).__new__(cls)
        return cls.__instances[cls]

    @classmethod
    @abstractmethod
    def locking(cls, **kwargs) -> Script:
        """
        :returns: locking script
        """
        raise NotImplementedError('ScriptType.locking')

    @classmethod
    @abstractmethod
    def unlocking(cls, **kwargs) -> Script:
        """
        :returns: unlocking script
        """
        raise NotImplementedError('ScriptType.unlocking')

    @classmethod
    @abstractmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        """
        :returns: estimated byte length of signed unlocking script
        """
        raise NotImplementedError('ScriptType.estimated_unlocking_byte_length')


class Unknown(ScriptType):  # pragma: no cover

    def __str__(self) -> str:
        return '<ScriptType:Unknown>'

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def locking(cls, **kwargs) -> Script:
        raise ValueError("don't know how to lock for script of unknown type")

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        raise ValueError("don't know how to unlock for script of unknown type")

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        raise ValueError("don't know how to unlock for script of unknown type")


class P2PKH(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:P2PKH>'

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def locking(cls, value: Union[str, bytes]) -> Script:
        """
        from address (str) or public key hash160 (bytes)
        """
        if isinstance(value, str):
            pkh: bytes = address_to_public_key_hash(value)
        elif isinstance(value, bytes):
            pkh: bytes = value
        else:
            raise TypeError("unsupported type to parse P2PKH locking script")
        assert len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH, 'invalid byte length of public key hash'
        return Script(OpCode.OP_DUP + OpCode.OP_HASH160 + encode_pushdata(pkh) + OpCode.OP_EQUALVERIFY + OpCode.OP_CHECKSIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signature: bytes = kwargs.get('signatures')[0]
        public_key: bytes = kwargs.get('public_key') or kwargs.get('private_keys')[0].public_key().serialize()
        sighash: SIGHASH = kwargs.get('sighash')
        return Script(encode_pushdata(signature + sighash.to_bytes(1, 'little')) + encode_pushdata(public_key))

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        if not kwargs.get('private_keys'):
            raise ValueError(f"can't estimate unlocking byte length without private keys")
        return 107 if kwargs.get('private_keys')[0].compressed else 139


class OpReturn(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:OP_RETURN>'

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def locking(cls, pushdatas: List[Union[str, bytes]]) -> Script:
        script: bytes = OpCode.OP_FALSE + OpCode.OP_RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode('utf-8')
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("unsupported type to parse OP_RETURN locking script")
            script += encode_pushdata(pushdata_bytes, minimal_push=False)
        return Script(script)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")


class P2PK(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:P2PK>'

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def locking(cls, public_key: Union[str, bytes]) -> Script:
        """
        from public key in format str or bytes
        """
        if isinstance(public_key, str):
            pk: bytes = bytes.fromhex(public_key)
        elif isinstance(public_key, bytes):
            pk: bytes = public_key
        else:
            raise TypeError("unsupported type to parse P2PK locking script")
        assert len(pk) in PUBLIC_KEY_BYTE_LENGTH_LIST, 'invalid byte length of public key'
        return Script(encode_pushdata(pk) + OpCode.OP_CHECKSIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signature: bytes = kwargs.get('signatures')[0]
        sighash: SIGHASH = kwargs.get('sighash')
        return Script(encode_pushdata(signature + sighash.to_bytes(1, 'little')))

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        return 73  # pragma: no cover


class BareMultisig(ScriptType):

    def __str__(self) -> str:  # pragma: no cover
        return '<ScriptType:BareMultisig>'

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def locking(cls, participants: List[Union[str, bytes]], threshold: int) -> Script:
        assert 1 <= threshold <= len(participants), 'bad threshold or number of participants'
        script: bytes = encode_int(threshold)
        for participant in participants:
            assert type(participant).__name__ in ['str', 'bytes'], 'unsupported public key type'
            if isinstance(participant, str):
                participant = bytes.fromhex(participant)
            assert len(participant) in PUBLIC_KEY_BYTE_LENGTH_LIST, 'invalid byte length of public key'
            script += encode_pushdata(participant)
        return Script(script + encode_int(len(participants)) + OpCode.OP_CHECKMULTISIG)

    @classmethod
    def unlocking(cls, **kwargs) -> Script:
        signatures: List[bytes] = kwargs.get('signatures')
        sighash: SIGHASH = kwargs.get('sighash')
        script: bytes = OpCode.OP_0
        for signature in signatures:
            script += encode_pushdata(signature + sighash.to_bytes(1, 'little'))
        return Script(script)

    @classmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:  # pragma: no cover
        if not kwargs.get('threshold') and not kwargs.get('private_keys'):
            raise ValueError(f"can't estimate unlocking byte length without threshold value")
        threshold = kwargs.get('threshold') if kwargs.get('threshold') else len(kwargs.get('private_keys'))
        return 1 + 73 * threshold
