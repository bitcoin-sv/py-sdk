import math
import re
from base64 import b64encode, b64decode
from contextlib import suppress
from typing import Tuple, Optional, Union

from typing_extensions import Literal

from .base58 import base58check_decode
from .constants import Network, ADDRESS_PREFIX_NETWORK_DICT, WIF_PREFIX_NETWORK_DICT, NUMBER_BYTE_LENGTH
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
