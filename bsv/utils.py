import math
import re
import struct
from base64 import b64encode, b64decode
from contextlib import suppress
from io import BytesIO
from secrets import randbits
from typing import Tuple, Optional, Union, Literal, List

from .base58 import base58check_decode
from .constants import Network, ADDRESS_PREFIX_NETWORK_DICT, WIF_PREFIX_NETWORK_DICT, NUMBER_BYTE_LENGTH
from .constants import OpCode
from .curve import curve


def unsigned_to_varint(num: int) -> bytes:
    """
    convert an unsigned int to varint.
    """
    if num < 0 or num > 0xffffffffffffffff:
        raise OverflowError(f"can't convert {num} to varint")
    if num <= 0xfc:
        return num.to_bytes(1, 'little')
    elif num <= 0xffff:
        return b'\xfd' + num.to_bytes(2, 'little')
    elif num <= 0xffffffff:
        return b'\xfe' + num.to_bytes(4, 'little')
    else:
        return b'\xff' + num.to_bytes(8, 'little')


def unsigned_to_bytes(num: int, byteorder: Literal['big', 'little'] = 'big') -> bytes:
    """
    convert an unsigned int to the least number of bytes as possible.
    """
    return num.to_bytes(math.ceil(num.bit_length() / 8) or 1, byteorder)


def decode_address(address: str) -> Tuple[bytes, Network]:
    """
    :returns: tuple (public_key_hash_bytes, network)
    """
    if not re.match(r'^[1mn][a-km-zA-HJ-NP-Z1-9]{24,33}$', address):
        # - a Bitcoin address is between 25 and 34 characters long;
        # - the address always starts with a 1, m, or n
        # - an address can contain all alphanumeric characters, with the exceptions of 0, O, I, and l.
        raise ValueError(f'invalid P2PKH address {address}')
    decoded = base58check_decode(address)
    prefix = decoded[:1]
    network = ADDRESS_PREFIX_NETWORK_DICT.get(prefix)
    return decoded[1:], network


def validate_address(address: str, network: Optional[Network] = None) -> bool:
    """
    :returns: True if address is a valid bitcoin legacy address (P2PKH)
    """
    with suppress(Exception):
        _, _network = decode_address(address)
        if network is not None:
            return _network == network
        return True
    return False


def address_to_public_key_hash(address: str) -> bytes:
    """
    :returns: convert P2PKH address to the corresponding public key hash
    """
    return decode_address(address)[0]


def decode_wif(wif: str) -> Tuple[bytes, bool, Network]:
    """
    :returns: tuple (private_key_bytes, compressed, network)
    """
    decoded = base58check_decode(wif)
    prefix = decoded[:1]
    network = WIF_PREFIX_NETWORK_DICT.get(prefix)
    if not network:
        raise ValueError(f'unknown WIF prefix {prefix.hex()}')
    if len(wif) == 52 and decoded[-1] == 1:
        return decoded[1:-1], True, network
    return decoded[1:], False, network


def deserialize_ecdsa_der(signature: bytes) -> Tuple[int, int]:
    """
    deserialize ECDSA signature from bitcoin strict DER to (r, s)
    """
    try:
        assert signature[0] == 0x30
        assert int(signature[1]) == len(signature) - 2
        # r
        assert signature[2] == 0x02
        r_len = int(signature[3])
        r = int.from_bytes(signature[4: 4 + r_len], 'big')
        # s
        assert signature[4 + r_len] == 0x02
        s_len = int(signature[5 + r_len])
        s = int.from_bytes(signature[-s_len:], 'big')
        return r, s
    except Exception:
        raise ValueError(f'invalid DER encoded {signature.hex()}')


def serialize_ecdsa_der(signature: Tuple[int, int]) -> bytes:
    """
    serialize ECDSA signature (r, s) to bitcoin strict DER format
    """
    r, s = signature
    # enforce low s value
    if s > curve.n // 2:
        s = curve.n - s
    # r
    r_bytes = r.to_bytes(NUMBER_BYTE_LENGTH, 'big').lstrip(b'\x00')
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    serialized = bytes([2, len(r_bytes)]) + r_bytes
    # s
    s_bytes = s.to_bytes(NUMBER_BYTE_LENGTH, 'big').lstrip(b'\x00')
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    serialized += bytes([2, len(s_bytes)]) + s_bytes
    return bytes([0x30, len(serialized)]) + serialized


def deserialize_ecdsa_recoverable(signature: bytes) -> Tuple[int, int, int]:
    """
    deserialize recoverable ECDSA signature from bytes to (r, s, recovery_id)
    """
    assert len(signature) == 65, 'invalid length of recoverable ECDSA signature'
    rec_id = signature[-1]
    assert 0 <= rec_id <= 3, f'invalid recovery id {rec_id}'
    r = int.from_bytes(signature[:NUMBER_BYTE_LENGTH], 'big')
    s = int.from_bytes(signature[NUMBER_BYTE_LENGTH:-1], 'big')
    return r, s, rec_id


def serialize_ecdsa_recoverable(signature: Tuple[int, int, int]) -> bytes:
    """
    serialize recoverable ECDSA signature from (r, s, recovery_id) to bytes
    """
    _r, _s, _rec_id = signature
    assert 0 <= _rec_id < 4, f'invalid recovery id {_rec_id}'
    r = _r.to_bytes(NUMBER_BYTE_LENGTH, 'big')
    s = _s.to_bytes(NUMBER_BYTE_LENGTH, 'big')
    rec_id = _rec_id.to_bytes(1, 'big')
    return r + s + rec_id


def serialize_text(text: str) -> bytes:
    """
    serialize plain text to bytes in format: varint_length + text.utf-8
    """
    message: bytes = text.encode('utf-8')
    return unsigned_to_varint(len(message)) + message


def text_digest(text: str) -> bytes:
    """
    :returns: the digest of arbitrary text when signing with bitcoin private key
    """
    return serialize_text('Bitcoin Signed Message:\n') + serialize_text(text)


def stringify_ecdsa_recoverable(signature: bytes, compressed: bool = True) -> str:
    """stringify serialize recoverable ECDSA signature
    :param signature: serialized recoverable ECDSA signature in "r (32 bytes) + s (32 bytes) + recovery_id (1 byte)"
    :param compressed: True if used compressed public key
    :returns: stringified recoverable signature formatted in base64
    """
    r, s, recovery_id = deserialize_ecdsa_recoverable(signature)
    prefix: int = 27 + recovery_id + (4 if compressed else 0)
    signature: bytes = prefix.to_bytes(1, 'big') + signature[:-1]
    return b64encode(signature).decode('ascii')


def unstringify_ecdsa_recoverable(signature: str) -> Tuple[bytes, bool]:
    """
    :returns: (serialized_recoverable_signature, used_compressed_public_key)
    """
    serialized = b64decode(signature)
    assert len(serialized) == 65, 'invalid length of recoverable ECDSA signature'
    prefix = serialized[0]
    assert 27 <= prefix < 35, f'invalid recoverable ECDSA signature prefix {prefix}'
    compressed = False
    if prefix >= 31:
        compressed = True
        prefix -= 4
    recovery_id = prefix - 27
    return serialized[1:] + recovery_id.to_bytes(1, 'big'), compressed


def bytes_to_bits(octets: Union[str, bytes]) -> str:
    """
    convert bytes to binary 0/1 string
    """
    b: bytes = octets if isinstance(octets, bytes) else bytes.fromhex(octets)
    bits: str = bin(int.from_bytes(b, 'big'))[2:]
    if len(bits) < len(b) * 8:
        bits = '0' * (len(b) * 8 - len(bits)) + bits
    return bits


def bits_to_bytes(bits: str) -> bytes:
    """
    convert binary 0/1 string to bytes
    """
    byte_length = math.ceil(len(bits) / 8) or 1
    return int(bits, 2).to_bytes(byte_length, byteorder='big')


def randbytes(length: int) -> bytes:
    """
    generate cryptographically secure random bytes
    """
    return randbits(length * 8).to_bytes(length, 'big')


def get_pushdata_code(byte_length: int) -> bytes:
    """
    :returns: the corresponding PUSHDATA opcode according to the byte length of pushdata
    """
    if byte_length <= 0x4b:
        return byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xff:
        # OP_PUSHDATA1
        return OpCode.OP_PUSHDATA1 + byte_length.to_bytes(1, 'little')
    elif byte_length <= 0xffff:
        # OP_PUSHDATA2
        return OpCode.OP_PUSHDATA2 + byte_length.to_bytes(2, 'little')
    elif byte_length <= 0xffffffff:
        # OP_PUSHDATA4
        return OpCode.OP_PUSHDATA4 + byte_length.to_bytes(4, 'little')
    else:
        raise ValueError("data too long to encode in a PUSHDATA opcode")


def encode_pushdata(pushdata: bytes, minimal_push: bool = True) -> bytes:
    """encode pushdata with proper opcode
    https://github.com/bitcoin-sv/bitcoin-sv/blob/v1.0.10/src/script/interpreter.cpp#L310-L337
    :param pushdata: bytes you want to push onto the stack in bitcoin script
    :param minimal_push: if True then push data following the minimal push rule
    """
    if minimal_push:
        if pushdata == b'':
            return OpCode.OP_0
        if len(pushdata) == 1 and 1 <= pushdata[0] <= 16:
            return bytes([OpCode.OP_1[0] + pushdata[0] - 1])
        if len(pushdata) == 1 and pushdata[0] == 0x81:
            return OpCode.OP_1NEGATE
    else:
        # non-minimal push requires pushdata != b''
        assert pushdata, 'empty pushdata'
    return get_pushdata_code(len(pushdata)) + pushdata


def encode_int(num: int) -> bytes:
    """
    encode a signed integer you want to push onto the stack in bitcoin script, following the minimal push rule
    """
    if num == 0:
        return OpCode.OP_0
    negative: bool = num < 0
    octets: bytearray = bytearray(unsigned_to_bytes(-num if negative else num, 'little'))
    if octets[-1] & 0x80:
        octets += b'\x00'
    if negative:
        octets[-1] |= 0x80
    return encode_pushdata(octets)


def to_hex(byte_array: bytes) -> str:
    return byte_array.hex()


def to_bytes(msg: Union[bytes, str], enc: Optional[str] = None) -> bytes:
    """Converts various message formats into a bytes object."""
    if isinstance(msg, bytes):
        return msg

    if not msg:
        return bytes()

    if isinstance(msg, str):
        if enc == 'hex':
            msg = ''.join(filter(str.isalnum, msg))
            if len(msg) % 2 != 0:
                msg = '0' + msg
            return bytes(int(msg[i:i + 2], 16) for i in range(0, len(msg), 2))
        elif enc == 'base64':
            import base64
            return base64.b64decode(msg)
        else:  # UTF-8 encoding
            return msg.encode('utf-8')

    return bytes(msg)


def to_utf8(arr: List[int]) -> str:
    """Converts an array of numbers to a UTF-8 encoded string."""
    return bytes(arr).decode('utf-8')


def encode(arr: List[int], enc: Optional[str] = None) -> Union[str, List[int]]:
    """Encodes an array of numbers into a specified encoding ('hex' or 'utf8')."""
    if enc == 'hex':
        return to_hex(bytes(arr))
    elif enc == 'utf8':
        return to_utf8(arr)
    return arr


def to_base64(byte_array: List[int]) -> str:
    """Converts an array of bytes into a base64 encoded string."""
    import base64
    return base64.b64encode(bytes(byte_array)).decode('ascii')


base58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def from_base58(str_: str) -> List[int]:
    """Converts a base58 string to a binary array."""
    if not str_ or not isinstance(str_, str):
        raise ValueError(f"Expected base58 string but got '{str_}'")
    if '0' in str_ or 'I' in str_ or 'O' in str_ or 'l' in str_:
        raise ValueError(f"Invalid base58 character in '{str_}'")

    lz = len(str_) - len(str_.lstrip('1'))
    psz = lz

    acc = 0
    for char in str_:
        acc = acc * 58 + base58chars.index(char)

    result = []
    while acc > 0:
        result.append(acc % 256)
        acc //= 256

    return [0] * psz + list(reversed(result))


def to_base58(bin_: List[int]) -> str:
    """Converts a binary array into a base58 string."""
    acc = 0
    for byte in bin_:
        acc = acc * 256 + byte

    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result = base58chars[mod] + result

    for byte in bin_:
        if byte == 0:
            result = '1' + result
        else:
            break

    return result


def to_base58_check(bin_: List[int], prefix: Optional[List[int]] = None) -> str:
    """Converts a binary array into a base58check string with a checksum."""
    import hashlib
    if prefix is None:
        prefix = [0]
    hash_ = hashlib.sha256(hashlib.sha256(bytes(prefix + bin_)).digest()).digest()
    return to_base58(prefix + bin_ + list(hash_[:4]))


def from_base58_check(str_: str, enc: Optional[str] = None, prefix_length: int = 1):
    """Converts a base58check string into a binary array after validating the checksum."""
    bin_ = from_base58(str_)
    prefix = bin_[:prefix_length]
    data = bin_[prefix_length:-4]
    checksum = bin_[-4:]

    import hashlib
    hash_ = hashlib.sha256(hashlib.sha256(bytes(prefix + data)).digest()).digest()
    if list(hash_[:4]) != checksum:
        raise ValueError('Invalid checksum')

    if enc == 'hex':
        prefix = to_hex(bytes(prefix))
        data = to_hex(bytes(data))

    return {'prefix': prefix, 'data': data}


class Writer(BytesIO):
    def __init__(self):
        super().__init__()

    def write(self, buf: bytes) -> 'Writer':
        super().write(buf)
        return self

    def write_reverse(self, buf: bytes) -> 'Writer':
        super().write(buf[::-1])
        return self

    def write_uint8(self, n: int) -> 'Writer':
        self.write(struct.pack('B', n))
        return self

    def write_int8(self, n: int) -> 'Writer':
        self.write(struct.pack('b', n))
        return self

    def write_uint16_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>H', n))
        return self

    def write_int16_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>h', n))
        return self

    def write_uint16_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<H', n))
        return self

    def write_int16_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<h', n))
        return self

    def write_uint32_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>I', n))
        return self

    def write_int32_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>i', n))
        return self

    def write_uint32_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<I', n))
        return self

    def write_int32_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<i', n))
        return self

    def write_uint64_be(self, n: int) -> 'Writer':
        self.write(struct.pack('>Q', n))
        return self

    def write_uint64_le(self, n: int) -> 'Writer':
        self.write(struct.pack('<Q', n))
        return self

    def write_var_int_num(self, n: int) -> 'Writer':
        self.write(self.var_int_num(n))
        return self

    def to_bytes(self) -> bytes:
        return self.getvalue()

    @staticmethod
    def var_int_num(n: int) -> bytes:
        return unsigned_to_varint(n)


class Reader(BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)

    def eof(self) -> bool:
        return self.tell() >= len(self.getvalue())

    def read(self, length: int = None) -> bytes:
        result = super().read(length)
        return result if result else None

    def read_reverse(self, length: int = None) -> bytes:
        data = self.read(length)
        return data[::-1] if data else None

    def read_uint8(self) -> Optional[int]:
        data = self.read(1)
        return data[0] if data else None

    def read_int8(self) -> Optional[int]:
        data = self.read(1)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint16_be(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_int16_be(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint16_le(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int16_le(self) -> Optional[int]:
        data = self.read(2)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_uint32_be(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='big') if data else None

    def read_int32_be(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='big', signed=True) if data else None

    def read_uint32_le(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='little') if data else None

    def read_int32_le(self) -> Optional[int]:
        data = self.read(4)
        return int.from_bytes(data, byteorder='little', signed=True) if data else None

    def read_var_int_num(self) -> Optional[int]:
        first_byte = self.read_uint8()
        if first_byte is None:
            return None
        if first_byte < 253:
            return first_byte
        elif first_byte == 253:
            return self.read_uint16_le()
        elif first_byte == 254:
            return self.read_uint32_le()
        elif first_byte == 255:
            data = self.read(8)
            return int.from_bytes(data, byteorder='little') if data else None
        else:
            raise ValueError("Invalid varint encoding")

    def read_var_int(self) -> Optional[bytes]:
        first_byte = self.read(1)
        if not first_byte:
            return None
        if first_byte[0] == 0xfd:
            return first_byte + (self.read(2) or b'')
        elif first_byte[0] == 0xfe:
            return first_byte + (self.read(4) or b'')
        elif first_byte[0] == 0xff:
            return first_byte + (self.read(8) or b'')
        else:
            return first_byte

    def read_bytes(self, byte_length: Optional[int] = None) -> bytes:
        result = self.read(byte_length)
        return result if result else b''

    def read_int(
            self, byte_length: int, byteorder: Literal["big", "little"] = "little"
    ) -> Optional[int]:
        octets = self.read_bytes(byte_length)
        if not octets:
            return None
        return int.from_bytes(octets, byteorder=byteorder)
    
    
def reverse_hex_byte_order(hex_str: str):
    return bytes.fromhex(hex_str)[::-1].hex()
