from .hash import hash256

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def _checksum(payload: bytes) -> bytes:
    return hash256(payload)[:4]


def b58_encode(payload: bytes) -> str:
    pad = 0
    for byte in payload:
        if byte == 0:
            pad += 1
        else:
            break
    prefix = '1' * pad
    num = int.from_bytes(payload, 'big')
    result = ''
    while num > 0:
        num, remaining = divmod(num, 58)
        result = BASE58_ALPHABET[remaining] + result
    return prefix + result


def base58check_encode(payload: bytes) -> str:
    return b58_encode(payload + _checksum(payload))


def b58_decode(encoded: str) -> bytes:
    pad = 0
    for char in encoded:
        if char == '1':
            pad += 1
        else:
            break
    prefix = b'\x00' * pad
    num = 0
    try:
        for char in encoded:
            num *= 58
            num += BASE58_ALPHABET.index(char)
    except Exception:
        raise ValueError(f'invalid base58 encoded {encoded}')
    # if num is 0 then (0).to_bytes will return b''
    return prefix + num.to_bytes((num.bit_length() + 7) // 8, 'big')


def base58check_decode(encoded: str) -> bytes:
    decoded = b58_decode(encoded)
    payload = decoded[:-4]
    decoded_checksum = decoded[-4:]
    hash_checksum = _checksum(payload)
    if decoded_checksum != hash_checksum:
        _msg = f'unmatched base58 checksum, expect {decoded_checksum.hex()} but actually {hash_checksum.hex()}'
        raise ValueError(_msg)
    return payload
