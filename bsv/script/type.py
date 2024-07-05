from abc import abstractmethod, ABCMeta
from typing import Union, List

from .script import Script
from ..constants import (
    OpCode,
    PUBLIC_KEY_HASH_BYTE_LENGTH,
    SIGHASH,
    PUBLIC_KEY_BYTE_LENGTH_LIST,
)
from ..utils import address_to_public_key_hash, encode_pushdata, encode_int


class ScriptTemplate(metaclass=ABCMeta):

    @abstractmethod
    def locking(cls, **kwargs) -> Script:
        """
        :returns: locking script
        """
        raise NotImplementedError("ScriptTemplate.locking")

    @abstractmethod
    def unlocking(cls, **kwargs) -> Script:
        """
        :returns: unlocking script
        """
        raise NotImplementedError("ScriptTemplate.unlocking")

    @abstractmethod
    def estimated_unlocking_byte_length(cls, **kwargs) -> int:
        """
        :returns: estimated byte length of signed unlocking script
        """
        raise NotImplementedError("ScriptTemplate.estimated_unlocking_byte_length")


class Unknown(ScriptTemplate):  # pragma: no cover

    def __str__(self) -> str:
        return "<ScriptTemplate:Unknown>"

    def __repr__(self) -> str:
        return self.__str__()

    def locking(self, **kwargs) -> Script:
        raise ValueError("don't know how to lock for script of unknown type")

    def unlocking(self, **kwargs) -> Script:
        raise ValueError("don't know how to unlock for script of unknown type")

    def estimated_unlocking_byte_length(self, **kwargs) -> int:
        raise ValueError("don't know how to unlock for script of unknown type")


class P2PKH(ScriptTemplate):

    def __init__(self, addr: Union[str, bytes]):
        """
        from address (str) or public key hash160 (bytes)
        """
        if isinstance(addr, str):
            pkh: bytes = address_to_public_key_hash(addr)
        elif isinstance(addr, bytes):
            pkh: bytes = addr
        else:
            raise TypeError("unsupported type to parse P2PKH locking script")

        assert (
            len(pkh) == PUBLIC_KEY_HASH_BYTE_LENGTH
        ), "invalid byte length of public key hash"

        self.pkh = pkh

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:P2PKH>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self) -> Script:
        return Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(self.pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIG
        )

    def unlocking(self, **kwargs) -> Script:
        signature: bytes = kwargs.get("signatures")[0]
        public_key: bytes = (
            kwargs.get("public_key")
            or kwargs.get("private_keys")[0].public_key().serialize()
        )
        sighash: SIGHASH = kwargs.get("sighash")
        return Script(
            encode_pushdata(signature + sighash.to_bytes(1, "little"))
            + encode_pushdata(public_key)
        )

    def estimated_unlocking_byte_length(self, **kwargs) -> int:
        if not kwargs.get("private_keys"):
            raise ValueError(
                f"can't estimate unlocking byte length without private keys"
            )
        return 107 if kwargs.get("private_keys")[0].compressed else 139


class OpReturn(ScriptTemplate):

    def __init__(self, pushdatas: List[Union[str, bytes]]):
        self.pushdatas = pushdatas

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:OP_RETURN>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self) -> Script:
        script: bytes = OpCode.OP_FALSE + OpCode.OP_RETURN
        for pushdata in self.pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode("utf-8")
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("unsupported type to parse OP_RETURN locking script")
            script += encode_pushdata(pushdata_bytes, minimal_push=False)
        return Script(script)

    def unlocking(self, **kwargs) -> Script:  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")

    def estimated_unlocking_byte_length(self, **kwargs) -> int:  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")


class P2PK(ScriptTemplate):

    def __init__(self, public_key: Union[str, bytes]):
        """
        from public key in format str or bytes
        """
        if isinstance(public_key, str):
            pk: bytes = bytes.fromhex(public_key)
        elif isinstance(public_key, bytes):
            pk: bytes = public_key
        else:
            raise TypeError("unsupported type to parse P2PK locking script")

        assert (
            len(pk) in PUBLIC_KEY_BYTE_LENGTH_LIST
        ), "invalid byte length of public key"
        self.pk = pk

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:P2PK>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self) -> Script:
        return Script(encode_pushdata(self.pk) + OpCode.OP_CHECKSIG)

    def unlocking(self, **kwargs) -> Script:
        signature: bytes = kwargs.get("signatures")[0]
        sighash: SIGHASH = kwargs.get("sighash")
        return Script(encode_pushdata(signature + sighash.to_bytes(1, "little")))

    def estimated_unlocking_byte_length(self, **kwargs) -> int:
        return 73  # pragma: no cover


class BareMultisig(ScriptTemplate):

    def __init__(self, participants: List[Union[str, bytes]], threshold: int):
        self.participants = []
        assert (
            1 <= threshold <= len(participants)
        ), "bad threshold or number of participants"
        for participant in participants:
            assert type(participant).__name__ in [
                "str",
                "bytes",
            ], "unsupported public key type"
            if isinstance(participant, str):
                participant = bytes.fromhex(participant)
            assert (
                len(participant) in PUBLIC_KEY_BYTE_LENGTH_LIST
            ), "invalid byte length of public key"
            self.participants.append(participant)
        self.threshold = threshold

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:BareMultisig>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self) -> Script:
        script: bytes = encode_int(self.threshold)
        for participant in self.participants:
            script += encode_pushdata(participant)
        return Script(script + encode_int(len(self.participants)) + OpCode.OP_CHECKMULTISIG)

    def unlocking(self, **kwargs) -> Script:
        signatures: List[bytes] = kwargs.get("signatures")
        sighash: SIGHASH = kwargs.get("sighash")
        script: bytes = OpCode.OP_0
        for signature in signatures:
            script += encode_pushdata(signature + sighash.to_bytes(1, "little"))
        return Script(script)

    def estimated_unlocking_byte_length(self, **kwargs) -> int:  # pragma: no cover
        if not kwargs.get("threshold") and not kwargs.get("private_keys"):
            raise ValueError(
                f"can't estimate unlocking byte length without threshold value"
            )
        threshold = (
            kwargs.get("threshold")
            if kwargs.get("threshold")
            else len(kwargs.get("private_keys"))
        )
        return 1 + 73 * threshold
