from typing import Union
from bsv.utils import unsigned_to_varint
from bsv.constants import OpCode


class Script:

    def __init__(self, script: Union[str, bytes, None] = None):
        """
        Create script from hex string or bytes
        """
        if script is None:
            self.script: bytes = b''
        elif isinstance(script, str):
            # script in hex string
            self.script: bytes = bytes.fromhex(script)
        elif isinstance(script, bytes):
            # script in bytes
            self.script: bytes = script
        else:
            raise TypeError('unsupported script type')

    def serialize(self) -> bytes:
        return self.script

    def hex(self) -> str:
        return self.script.hex()

    def byte_length(self) -> int:
        return len(self.script)

    size = byte_length

    def byte_length_varint(self) -> bytes:
        return unsigned_to_varint(self.byte_length())

    size_varint = byte_length_varint

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Script):
            return self.script == o.script
        return super().__eq__(o)

    def __str__(self) -> str:
        return self.script.hex()

    def __repr__(self) -> str:
        return self.__str__()

    def from_asm(self, asm: str):
        chunks = []
        tokens = asm.split(' ')
        i = 0
        while i < len(tokens):
            token = tokens[i]
            op_code = None
            op_code_num = None
            if token.startswith('OP_') and token in OpCode.__dict__:
                op_code = token
                op_code_num = OpCode.__dict__[token]

            if token == '0':
                op_code_num = 0
                chunks.append({'op': op_code_num})
                i += 1
            elif token == '-1':
                op_code_num = OpCode.OP_1NEGATE
                chunks.append({'op': op_code_num})
                i += 1
            elif op_code is None:
                hex_str = tokens[i]
                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str
                arr = bytearray.fromhex(hex_str)
                if arr.hex() != hex_str:
                    raise ValueError('Invalid hex string in script')
                length = len(arr)
                if 0 <= length < OpCode.OP_PUSHDATA1:
                    op_code_num = length
                elif length < 2 ** 8:
                    op_code_num = OpCode.OP_PUSHDATA1
                elif length < 2 ** 16:
                    op_code_num = OpCode.OP_PUSHDATA2
                elif length < 2 ** 32:
                    op_code_num = OpCode.OP_PUSHDATA4
                chunks.append({'data': arr, 'op': op_code_num})
                i += 1
            elif op_code_num in [OpCode.OP_PUSHDATA1, OpCode.OP_PUSHDATA2, OpCode.OP_PUSHDATA4]:
                chunks.append({'data': bytearray.fromhex(tokens[i + 2]), 'op': op_code_num})
                i += 3
            else:
                chunks.append({'op': op_code_num})
                i += 1
        self.script = chunks

    def to_asm(self):
        asm_str = ''
        for chunk in self.script:
            asm_str += self._chunk_to_string(chunk)

        return asm_str[1:]

    def _chunk_to_string(self, chunk) -> str:
        if 'op' in chunk:
            for name, code in OpCode.__dict__.items():
                if chunk['op'] == code:
                    return ' ' + name
        if 'data' in chunk:
            return ' ' + chunk['data'].hex()
        return ' unknown'
