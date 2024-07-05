import math
from contextlib import suppress
from io import BytesIO
from typing import List, Optional, Union, Dict, Any, Literal

from .constants import SIGHASH, Network
from .constants import (
    TRANSACTION_VERSION,
    TRANSACTION_LOCKTIME,
    TRANSACTION_SEQUENCE,
    TRANSACTION_FEE_RATE,
)
from .hash import hash256
from .keys import PrivateKey
from .script.script import Script
from .script.type import ScriptType, P2PKH, OpReturn, Unknown
from .broadcaster import Broadcaster, BroadcastResponse
from .broadcasters import default_broadcaster
from .chaintracker import ChainTracker
from .chaintrackers import default_chain_tracker
from .utils import unsigned_to_varint, Reader, Writer
from .merkle_path import MerklePath


class InsufficientFunds(ValueError):
    pass

class TxInput:

    def __init__(
        self,
        source_transaction = None,
        source_txid: Optional[str] = None,
        source_output_index: int = 0,
        unlocking_script: Optional[Script] = None,
        script_type: Optional[ScriptType] = Unknown,
        private_keys: Optional[List[PrivateKey]] = None,
        sequence: int = TRANSACTION_SEQUENCE,
        sighash: SIGHASH = SIGHASH.ALL_FORKID,
    ):
        utxo = None
        if source_transaction:
            utxo = source_transaction.outputs[source_output_index]

        self.txid: str = source_txid 
        self.vout: int = source_output_index
        self.value: int = utxo.value if utxo else None
        self.private_keys: List[PrivateKey] = private_keys or []
        self.script_type: ScriptType = script_type
        self.locking_script: Script = utxo.locking_script if utxo else None
        
        self.source_transaction = source_transaction

        self.unlocking_script: Script = unlocking_script
        self.sequence: int = sequence
        self.sighash: SIGHASH = sighash

    def serialize(self) -> bytes:
        stream = BytesIO()
        stream.write(bytes.fromhex(self.txid)[::-1])
        stream.write(self.vout.to_bytes(4, "little"))
        stream.write(
            self.unlocking_script.byte_length_varint()
            if self.unlocking_script
            else b"\x00"
        )
        stream.write(
            self.unlocking_script.serialize() if self.unlocking_script else b""
        )
        stream.write(self.sequence.to_bytes(4, "little"))
        return stream.getvalue()

    def __str__(self) -> str:  # pragma: no cover
        return f"<TxInput outpoint={self.txid}:{self.vout} value={self.value} locking_script={self.locking_script}>"

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, stream: Union[str, bytes, Reader]) -> Optional["TxInput"]:
        with suppress(Exception):
            stream = (
                stream
                if isinstance(stream, Reader)
                else Reader(
                    stream if isinstance(stream, bytes) else bytes.fromhex(stream)
                )
            )
            txid = stream.read_bytes(32)[::-1]
            assert len(txid) == 32
            vout = stream.read_int(4)
            assert vout is not None
            script_length = stream.read_var_int_num()
            assert script_length is not None
            unlocking_script_bytes = stream.read_bytes(script_length)
            sequence = stream.read_int(4)
            assert sequence is not None
            
            return TxInput(
                source_txid=txid.hex(),
                source_output_index=vout,
                unlocking_script=Script(unlocking_script_bytes),
                sequence=sequence,
            )

        return None


class TxOutput:

    def __init__(
        self,
        out: Union[str, List[Union[str, bytes]], Script],
        value: int = 0,
        script_type: ScriptType = Unknown(),
    ):
        self.value = value
        if isinstance(out, str):
            # from address
            self.locking_script: Script = P2PKH.locking(out)
            self.script_type: ScriptType = P2PKH()
        elif isinstance(out, List):
            # from list of pushdata
            self.locking_script: Script = OpReturn.locking(out)
            self.script_type: ScriptType = OpReturn()
        elif isinstance(out, Script):
            # from locking script
            self.locking_script: Script = out
            self.script_type: ScriptType = script_type
        else:
            raise TypeError("unsupported transaction output type")

    def serialize(self) -> bytes:
        return b"".join(
            [
                self.value.to_bytes(8, "little"),
                self.locking_script.byte_length_varint(),
                self.locking_script.serialize(),
            ]
        )

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"<TxOutput value={self.value} locking_script={self.locking_script.hex()}>"
        )

    def __repr__(self) -> str:  # pragma: no cover
        return self.__str__()

    @classmethod
    def from_hex(cls, stream: Union[str, bytes, Reader]) -> Optional["TxOutput"]:
        with suppress(Exception):
            stream = (
                stream
                if isinstance(stream, Reader)
                else Reader(
                    stream if isinstance(stream, bytes) else bytes.fromhex(stream)
                )
            )
            value = stream.read_int(8)
            assert value is not None
            script_length = stream.read_var_int_num()
            assert script_length is not None
            locking_script_bytes = stream.read_bytes(script_length)
            return TxOutput(out=Script(locking_script_bytes), value=value)
        return None


class Transaction:

    def __init__(
        self,
        tx_inputs: Optional[List[TxInput]] = None,
        tx_outputs: Optional[List[TxOutput]] = None,
        version: int = TRANSACTION_VERSION,
        locktime: int = TRANSACTION_LOCKTIME,
        merkle_path: Optional[MerklePath] = None,
        fee_rate: Optional[float] = None,
        **kwargs,
    ):
        self.inputs: List[TxInput] = tx_inputs or []
        self.outputs: List[TxOutput] = tx_outputs or []
        self.version: int = version
        self.locktime: int = locktime
        self.merkle_path = merkle_path
        self.fee_rate: float = (
            fee_rate if fee_rate is not None else TRANSACTION_FEE_RATE
        )

        self.kwargs: Dict[str, Any] = dict(**kwargs) or {}

    def serialize(self) -> bytes:
        raw = self.version.to_bytes(4, "little")
        raw += unsigned_to_varint(len(self.inputs))
        for tx_input in self.inputs:
            raw += tx_input.serialize()
        raw += unsigned_to_varint(len(self.outputs))
        for tx_output in self.outputs:
            raw += tx_output.serialize()
        raw += self.locktime.to_bytes(4, "little")
        return raw

    def add_input(
        self, tx_input: TxInput
    ) -> "Transaction":  # pragma: no cover
        if isinstance(tx_input, TxInput):
            self.inputs.append(tx_input)
        elif isinstance(tx_input, Unspent):
            self.inputs.append(TxInput(tx_input))
        else:
            raise TypeError("unsupported transaction input type")
        return self

    def add_inputs(self, tx_inputs: List[TxInput]) -> "Transaction":
        for tx_input in tx_inputs:
            self.add_input(tx_input)
        return self

    def add_output(self, tx_output: TxOutput) -> "Transaction":  # pragma: no cover
        self.outputs.append(tx_output)
        return self

    def add_outputs(self, tx_outputs: List[TxOutput]) -> "Transaction":
        for tx_output in tx_outputs:
            self.add_output(tx_output)
        return self

    def hex(self) -> str:  # pragma: no cover
        return self.serialize().hex()

    raw = hex

    def txid(self) -> str:
        return self.hash()[::-1].hex()
    
    def hash(self) -> bytes:
        return hash256(self.serialize())

    def _digest(
        self,
        tx_input: TxInput,
        hash_prevouts: bytes,
        hash_sequence: bytes,
        hash_outputs: bytes,
    ) -> bytes:
        """
        BIP-143 https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
         1. nVersion of the transaction (4-byte little endian)
         2. hashPrevouts (32-byte hash)
         3. hashSequence (32-byte hash)
         4. outpoint (32-byte hash + 4-byte little endian)
         5. scriptCode of the input (serialized as scripts inside CTxOuts)
         6. value of the output spent by this input (8-byte little endian)
         7. nSequence of the input (4-byte little endian)
         8. hashOutputs (32-byte hash)
         9. nLocktime of the transaction (4-byte little endian)
        10. sighash type of the signature (4-byte little endian)
        """
        stream = BytesIO()
        # 1
        stream.write(self.version.to_bytes(4, "little"))
        # 2
        stream.write(hash_prevouts)
        # 3
        stream.write(hash_sequence)
        # 4
        stream.write(bytes.fromhex(tx_input.txid)[::-1])
        stream.write(tx_input.vout.to_bytes(4, "little"))
        # 5
        stream.write(tx_input.locking_script.byte_length_varint())
        stream.write(tx_input.locking_script.serialize())
        # 6
        stream.write(tx_input.value.to_bytes(8, "little"))
        # 7
        stream.write(tx_input.sequence.to_bytes(4, "little"))
        # 8
        stream.write(hash_outputs)
        # 9
        stream.write(self.locktime.to_bytes(4, "little"))
        # 10
        stream.write(tx_input.sighash.to_bytes(4, "little"))
        return stream.getvalue()

    def digests(self) -> List[bytes]:
        """
        :returns: the digests of unsigned transaction
        """
        _hash_prevouts = hash256(
            b"".join(
                bytes.fromhex(_in.txid)[::-1] + _in.vout.to_bytes(4, "little")
                for _in in self.inputs
            )
        )
        _hash_sequence = hash256(
            b"".join(_in.sequence.to_bytes(4, "little") for _in in self.inputs)
        )
        _hash_outputs = hash256(
            b"".join(tx_output.serialize() for tx_output in self.outputs)
        )
        digests = []
        for i in range(len(self.inputs)):
            sighash = self.inputs[i].sighash
            # hash previous outs
            if not sighash & SIGHASH.ANYONECANPAY:
                # if anyone can pay is not set
                hash_prevouts = _hash_prevouts
            else:
                hash_prevouts = b"\x00" * 32
            # hash sequence
            if (
                not sighash & SIGHASH.ANYONECANPAY
                and sighash & 0x1F != SIGHASH.SINGLE
                and sighash & 0x1F != SIGHASH.NONE
            ):
                # if none of anyone can pay, single, none is set
                hash_sequence = _hash_sequence
            else:
                hash_sequence = b"\x00" * 32
            # hash outputs
            if sighash & 0x1F != SIGHASH.SINGLE and sighash & 0x1F != SIGHASH.NONE:
                # if neither single nor none
                hash_outputs = _hash_outputs
            elif sighash & 0x1F == SIGHASH.SINGLE and i < len(self.outputs):
                # if single and the input index is smaller than the number of outputs
                hash_outputs = hash256(self.outputs[i].serialize())
            else:
                hash_outputs = b"\x00" * 32
            digests.append(
                self._digest(self.inputs[i], hash_prevouts, hash_sequence, hash_outputs)
            )
        return digests

    def digest(self, index: int) -> bytes:
        """
        :returns: digest of the input specified by index
        """
        assert (
            0 <= index < len(self.inputs)
        ), f"index out of range [0, {len(self.inputs)})"
        return self.digests()[index]

    def sign(self, bypass: bool = True, **kwargs) -> "Transaction":  # pragma: no cover
        """
        :bypass: if True then ONLY sign inputs which unlocking script is None, otherwise sign all the inputs
        sign all inputs according to their script type
        """
        digests = self.digests()
        for i in range(len(self.inputs)):
            tx_input = self.inputs[i]
            if tx_input.unlocking_script is None or not bypass:
                signatures: List[bytes] = [
                    private_key.sign(digests[i])
                    for private_key in tx_input.private_keys
                ]
                payload = {
                    "signatures": signatures,
                    "private_keys": tx_input.private_keys,
                    "sighash": tx_input.sighash,
                }
                tx_input.unlocking_script = tx_input.script_type.unlocking(
                    **payload, **{**self.kwargs, **kwargs}
                )
        return self

    def total_value_in(self) -> int:
        return sum([tx_input.value for tx_input in self.inputs])

    def total_value_out(self) -> int:
        return sum([tx_output.value for tx_output in self.outputs])

    def fee(self) -> int:
        """
        :returns: actual fee paid of this transaction under the current state
        """
        return self.total_value_in() - self.total_value_out()

    def byte_length(self) -> int:
        """
        :returns: actual byte length of this transaction under the current state
        """
        return len(self.serialize())

    size = byte_length

    def estimated_byte_length(self, **kwargs) -> int:
        """
        :returns: estimated byte length of this transaction after signing
        if transaction has already signed, it will return the same value as function byte_length
        """
        estimated_length = (
            4
            + len(unsigned_to_varint(len(self.inputs)))
            + len(unsigned_to_varint(len(self.outputs)))
            + 4
        )
        for tx_input in self.inputs:
            if tx_input.unlocking_script is not None:
                # unlocking script already set
                estimated_length += len(tx_input.serialize())
            else:
                estimated_length += (
                    41
                    + tx_input.script_type.estimated_unlocking_byte_length(
                        private_keys=tx_input.private_keys, **{**self.kwargs, **kwargs}
                    )
                )
        for tx_output in self.outputs:
            estimated_length += (
                8
                + len(tx_output.locking_script.byte_length_varint())
                + tx_output.locking_script.byte_length()
            )
        return estimated_length

    estimated_size = estimated_byte_length

    def estimated_fee(self) -> int:
        """
        :returns: estimated fee of this transaction after signing
        """
        return math.ceil(self.fee_rate * self.estimated_byte_length())

    def add_change(self, change_address: Optional[str] = None) -> "Transaction":
        # byte length increased after adding a P2PKH change output
        size_increased = (
            34
            + len(unsigned_to_varint(len(self.outputs) + 1))
            - len(unsigned_to_varint(len(self.outputs)))
        )
        # then we know the estimated byte length after signing, of this transaction with a change output
        fee_expected = math.ceil(
            self.fee_rate * (self.estimated_byte_length() + size_increased)
        )
        fee_overpaid = self.fee() - fee_expected
        if fee_overpaid > 0:  # pragma: no cover
            change_output: Optional[TxOutput] = None
            if not change_address:
                for tx_input in self.inputs:
                    if tx_input.script_type == P2PKH():
                        change_output = TxOutput(
                            out=tx_input.locking_script,
                            value=fee_overpaid,
                            script_type=P2PKH(),
                        )
                        break
            else:
                change_output = TxOutput(out=change_address, value=fee_overpaid)
            assert change_output, "can't parse any address from transaction inputs"
            self.add_output(change_output)
        return self

    def broadcast(self, broadcaster: Broadcaster = default_broadcaster(), check_fee: bool = True) -> BroadcastResponse:  # pragma: no cover
        fee_expected = self.estimated_fee()
        if check_fee and self.fee() < fee_expected:
            raise InsufficientFunds(
                f"require {self.total_value_out() + fee_expected} satoshi but only {self.total_value_in()}"
            )
        return broadcaster.broadcast(self.raw())

    @classmethod
    def from_hex(cls, stream: Union[str, bytes, Reader]) -> Optional["Transaction"]:
        with suppress(Exception):
            if isinstance(stream, str):
                return cls.from_reader(Reader(bytes.fromhex(stream)))
            elif isinstance(stream, bytes):
                return cls.from_reader(Reader(stream))
            return cls.from_reader(stream)
        return None

    @classmethod
    def from_BEEF(cls, stream: Union[str, bytes, Reader]) -> "Transaction":
        stream = (
            stream
            if isinstance(stream, Reader)
            else Reader(
                stream if isinstance(stream, bytes) else bytes.fromhex(stream)
            )
        )
        version = stream.read_uint32_le()
        if version != 4022206465:
            raise ValueError(
                f"Invalid BEEF version. Expected 4022206465, received {version}."
            )

        number_of_BUMPs = stream.read_var_int_num()
        BUMPs = []
        for _ in range(number_of_BUMPs):
            BUMPs.append(MerklePath.from_reader(stream))

        number_of_transactions = stream.read_var_int_num()
        transactions = {}
        last_TXID = None
        for i in range(number_of_transactions):
            tx = cls.from_reader(stream)
            obj = {"tx": tx}
            txid = tx.txid()
            if i + 1 == number_of_transactions:
                last_TXID = txid
            has_bump = bool(stream.read_uint8())
            if has_bump:
                obj["pathIndex"] = stream.read_var_int_num()
            transactions[txid] = obj

        def add_path_or_inputs(obj):
            if "pathIndex" in obj:
                path = BUMPs[obj["pathIndex"]]
                if not isinstance(path, MerklePath):
                    raise ValueError("Invalid merkle path index found in BEEF!")
                obj["tx"].merkle_path = path
            else:
                for tx_input in obj["tx"].inputs:
                    source_obj = transactions[tx_input.txid]
                    if not isinstance(source_obj, dict):
                        raise ValueError(
                            f"Reference to unknown TXID in BUMP: {tx_input.txid}"
                        )
                    tx_input.source_transaction = source_obj["tx"]
                    add_path_or_inputs(source_obj)

        add_path_or_inputs(transactions[last_TXID])
        return transactions[last_TXID]["tx"]
    
    def to_BEEF(self) -> bytes:
        writer = Writer()
        writer.write_uint32_le(4022206465)
        BUMPs = []
        txs = []

        def add_paths_and_inputs(tx):
            obj = {'tx': tx}
            has_proof = isinstance(tx.merkle_path, MerklePath)
            if has_proof:
                added = False
                for i, bump in enumerate(BUMPs):
                    if bump == tx.merkle_path:
                        obj['path_index'] = i
                        added = True
                        break
                    if bump.block_height == tx.merkle_path.block_height:
                        root_a = bump.compute_root()
                        root_b = tx.merkle_path.compute_root()
                        if root_a == root_b:
                            bump.combine(tx.merkle_path)
                            obj['path_index'] = i
                            added = True
                            break
                if not added:
                    obj['path_index'] = len(BUMPs)
                    BUMPs.append(tx.merkle_path)
            txs.insert(0, obj)
            if not has_proof:
                for tx_input in tx.inputs:
                    if not isinstance(tx_input.source_transaction, Transaction):
                        raise ValueError('A required source transaction is missing!')
                    add_paths_and_inputs(tx_input.source_transaction)

        add_paths_and_inputs(self)

        writer.write_var_int_num(len(BUMPs))
        for b in BUMPs:
            writer.write(b.to_binary())
        writer.write_var_int_num(len(txs))
        for t in txs:
            writer.write(t['tx'].serialize())
            if 'path_index' in t:
                writer.write_uint8(1)
                writer.write_var_int_num(t['path_index'])
            else:
                writer.write_uint8(0)
        return writer.to_bytes()

    @classmethod
    def from_reader(cls, reader: Reader) -> 'Transaction':
        t = cls()
        t.version = reader.read_uint32_le()
        assert t.version is not None
        inputs_count = reader.read_var_int_num()
        assert inputs_count is not None
        for _ in range(inputs_count):
            _input = TxInput.from_hex(reader)
            assert _input is not None
            t.inputs.append(_input)
        outputs_count = reader.read_var_int_num()
        assert outputs_count is not None
        for _ in range(outputs_count):
            _output = TxOutput.from_hex(reader)
            assert _output is not None
            t.outputs.append(_output)
        t.locktime = reader.read_uint32_le()
        assert t.locktime is not None
        return t
    
    async def verify(self, chaintracker: Optional[ChainTracker] = default_chain_tracker(), scripts_only = False) -> bool:
        if isinstance(self.merkle_path, object) and not scripts_only:
            proof_valid = self.merkle_path.verify(self.txid(), chaintracker)
            if proof_valid:
                return True
            
        input_total = 0
        for i, tx_input in enumerate(self.inputs):
            if not tx_input.get('source_transaction', False):
                raise ValueError(f"Verification failed because the input at index {i} of transaction {self.txid()} is missing an associated source transaction. This source transaction is required for transaction verification because there is no merkle proof for the transaction spending a UTXO it contains.")
            if not tx_input.get('unlocking_script', False):
                raise ValueError(f"Verification failed because the input at index {i} of transaction {self.txid()} is missing an associated unlocking script. This script is required for transaction verification because there is no merkle proof for the transaction spending the UTXO.")
            
            source_output = tx_input.source_transaction.outputs[tx_input.vout]
            input_total += source_output.satoshis

            input_verified = tx_input.source_transaction.verify(chaintracker)
            if not input_verified:
                return False

            other_inputs = self.inputs[:i] + self.inputs[i+1:]
            # TODO: Implement spend interface...
            #spend = Spend(
            #    txid=tx_input.source_transaction.txid(),
            #    vout=tx_input.vout,
            #    locking_script=source_output.locking_script,
            #    value=source_output.value,
            #    version=self.version,
            #    other_inputs=other_inputs,
            #    unlocking_script=tx_input.unlocking_script,
            #    sequence=tx_input.sequence,
            #    inputIndex=i,
            #    outputs=self.outputs,
            #    locktime=self.locktime
            #)
            #spend_valid = spend.validate()
            #if not spend_valid:
            #    return False

        output_total = 0
        for out in self.outputs:
            if not isinstance(out.satoshis, int):
                raise ValueError("Every output must have a defined amount during transaction verification.")
            output_total += out.satoshis

        return output_total <= input_total
    
    @classmethod
    def parse_script_offsets(cls, bin: Union[bytes, str]) -> Dict[str, List[Dict[str, int]]]:
        """
        Since the validation of blockchain data is atomically transaction data validation,
        any application seeking to validate data in output scripts must store the entire transaction as well.
        Since the transaction data includes the output script data, saving a second copy of potentially
        large scripts can bloat application storage requirements.

        This function efficiently parses binary transaction data to determine the offsets and lengths of each script.
        This supports the efficient retrieval of script data from transaction data.

        @param bin: binary transaction data or hex string
        @returns: {
            inputs: { vin: number, offset: number, length: number }[]
            outputs: { vout: number, offset: number, length: number }[]
        }
        """
        if isinstance(bin, str):
            bin = bytes.fromhex(bin)
        
        br = Reader(bin)
        inputs: List[Dict[str, int]] = []
        outputs: List[Dict[str, int]] = []

        br.read(4) # skip version
        inputs_length = br.read_var_int_num()
        for i in range(inputs_length):
            br.read(36) # skip txid and vout
            script_length = br.read_var_int_num()
            inputs.append({'vin': i, 'offset': br.tell(), 'length': script_length})
            br.read(script_length + 4) # script and sequence

        outputs_length = br.read_var_int_num()
        for i in range(outputs_length):
            br.read(8)
            script_length = br.read_var_int_num()
            outputs.append({'vout': i, 'offset': br.tell(), 'length': script_length})
            br.read(script_length)  # skip script

        return {'inputs': inputs, 'outputs': outputs}
