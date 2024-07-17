from abc import abstractmethod, ABCMeta
from typing import Union, List

from .script import Script
from .unlocking_template import UnlockingScriptTemplate
from ..constants import (
    OpCode,
    PUBLIC_KEY_HASH_BYTE_LENGTH,
    PUBLIC_KEY_BYTE_LENGTH_LIST,
)
from ..keys import PrivateKey
from ..utils import address_to_public_key_hash, encode_pushdata, encode_int


def to_unlock_script_template(sign, estimated_unlocking_byte_length):
    class_attrs = {"sign": sign, "estimated_unlocking_byte_length": estimated_unlocking_byte_length}

    dynamic_class = type("UnlockScriptTemplateImpl", (UnlockingScriptTemplate,), class_attrs)

    return dynamic_class


class ScriptTemplate(metaclass=ABCMeta):

    @abstractmethod
    def locking(self, **kwargs) -> Script:
        """
        :returns: locking script
        """
        raise NotImplementedError("ScriptTemplate.locking")

    @abstractmethod
    def unlocking(self, **kwargs) -> UnlockingScriptTemplate:
        """
        :returns: sign (function), estimated_unlocking_byte_length (function)
        """
        raise NotImplementedError("ScriptTemplate.unlocking")


class Unknown(ScriptTemplate):  # pragma: no cover

    def __str__(self) -> str:
        return "<ScriptTemplate:Unknown>"

    def __repr__(self) -> str:
        return self.__str__()

    def locking(self, **kwargs) -> Script:
        raise ValueError("don't know how to lock for script of unknown type")

    def unlocking(self, **kwargs):
        raise ValueError("don't know how to unlock for script of unknown type")


class P2PKH(ScriptTemplate):

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:P2PKH>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self, addr: Union[str, bytes]) -> Script:
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

        return Script(
            OpCode.OP_DUP
            + OpCode.OP_HASH160
            + encode_pushdata(pkh)
            + OpCode.OP_EQUALVERIFY
            + OpCode.OP_CHECKSIG
        )

    def unlocking(self, private_key: PrivateKey):
        def sign(tx, input_index) -> Script:
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash

            signature = private_key.sign(tx.preimage(input_index))

            public_key: bytes = private_key.public_key().serialize()
            return Script(
                encode_pushdata(signature + sighash.to_bytes(1, "little"))
                + encode_pushdata(public_key)
            )

        def estimated_unlocking_byte_length() -> int:
            return 107 if private_key.compressed else 139

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)


class OpReturn(ScriptTemplate):

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:OP_RETURN>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self, pushdatas: List[Union[str, bytes]]) -> Script:
        script: bytes = OpCode.OP_FALSE + OpCode.OP_RETURN
        for pushdata in pushdatas:
            if isinstance(pushdata, str):
                pushdata_bytes: bytes = pushdata.encode("utf-8")
            elif isinstance(pushdata, bytes):
                pushdata_bytes: bytes = pushdata
            else:
                raise TypeError("unsupported type to parse OP_RETURN locking script")
            script += encode_pushdata(pushdata_bytes, minimal_push=False)
        return Script(script)

    def unlocking(self, **kwargs):  # pragma: no cover
        raise ValueError("OP_RETURN cannot be unlocked")


class P2PK(ScriptTemplate):

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:P2PK>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self, public_key: Union[str, bytes]) -> Script:
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

        return Script(encode_pushdata(pk) + OpCode.OP_CHECKSIG)

    def unlocking(self, private_key: PrivateKey):
        def sign(tx, input_index) -> Script:
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash

            signature = private_key.sign(tx.preimage(input_index))
            return Script(encode_pushdata(signature + sighash.to_bytes(1, "little")))

        def estimated_unlocking_byte_length() -> int:
            return 73

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)


class BareMultisig(ScriptTemplate):

    def __str__(self) -> str:  # pragma: no cover
        return "<ScriptTemplate:BareMultisig>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    def locking(self, participants: List[Union[str, bytes]], threshold: int) -> Script:
        assert (
                1 <= threshold <= len(participants)
        ), "bad threshold or number of participants"

        participants_parsed = []
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
            participants_parsed.append(participant)
        script: bytes = encode_int(threshold)
        for participant in participants_parsed:
            script += encode_pushdata(participant)
        return Script(script + encode_int(len(participants)) + OpCode.OP_CHECKMULTISIG)

    def unlocking(self, private_keys: List[PrivateKey]):
        def sign(tx, input_index) -> Script:
            tx_input = tx.inputs[input_index]
            sighash = tx_input.sighash

            script: bytes = OpCode.OP_0
            for private_key in private_keys:
                signature = private_key.sign(tx.preimage(input_index))
                script += encode_pushdata(signature + sighash.to_bytes(1, "little"))
            return Script(script)

        def estimated_unlocking_byte_length() -> int:
            return 1 + 73 * len(private_keys)

        return to_unlock_script_template(sign, estimated_unlocking_byte_length)
