import hashlib

import ecdsa
import pytest

from bsv.constants import Network
from bsv.curve import Point
from bsv.hash import sha256
from bsv.keys import PrivateKey, PublicKey, verify_signed_text
from bsv.utils import text_digest, unstringify_ecdsa_recoverable

private_key_hex = 'f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62'
private_key_bytes = bytes.fromhex(private_key_hex)
private_key_int = int(private_key_hex, 16)
private_key = PrivateKey(private_key_int)

x = 'e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789'
y = '97693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2'
point = Point(int(x, 16), int(y, 16))
public_key = PublicKey(point)

address_compressed_main = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
address_uncompressed_main = '1BVHzn1J8VZWRuVWbPrj2Szx1j7hHdt5zP'
address_compressed_test = 'mqBuyzdHfD87VfgxaYeM9pex3sJn4ihYHY'
address_uncompressed_test = 'mr1FHq6GwWzmD1y8Jxq6rNDGsiiQ9caF7r'


def test_public_key():
    public_key_compressed = f'02{x}'
    public_key_uncompressed = f'04{x}{y}'

    assert public_key.point() == point
    assert public_key.hex() == public_key_compressed
    assert public_key.hex(compressed=True) == public_key_compressed
    assert public_key.hex(compressed=False) == public_key_uncompressed

    assert public_key.address() == address_compressed_main
    assert public_key.address(compressed=True, network=Network.MAINNET) == address_compressed_main
    assert public_key.address(compressed=False, network=Network.MAINNET) == address_uncompressed_main
    assert public_key.address(compressed=True, network=Network.TESTNET) == address_compressed_test
    assert public_key.address(compressed=False, network=Network.TESTNET) == address_uncompressed_test

    assert PublicKey(public_key_compressed) == public_key
    assert PublicKey(public_key_compressed).address() == address_compressed_main

    assert PublicKey(public_key_uncompressed) == public_key
    assert PublicKey(public_key_uncompressed).address() == address_uncompressed_main

    assert PublicKey(bytes.fromhex(public_key_compressed)) == public_key

    with pytest.raises(TypeError, match=r'unsupported public key type'):
        # noinspection PyTypeChecker
        PublicKey(1.23)


def test_private_key():
    assert private_key == PrivateKey.from_hex(private_key_hex)
    assert private_key.public_key() == public_key
    assert private_key.hex() == private_key_hex
    assert private_key.serialize() == private_key_bytes
    assert private_key.int() == private_key_int

    priv_key_wif_compressed_main = 'L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9'
    priv_key_wif_uncompressed_main = '5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U'
    priv_key_wif_compressed_test = 'cVwfreZB3i8iv9JpdSStd9PWhZZGGJCFLS4rEKWfbkahibwhticA'
    priv_key_wif_uncompressed_test = '93UnxexmsTYCmDJdctz4zacuwxQd5prDmH6rfpEyKkQViAVA3me'

    assert private_key.wif() == priv_key_wif_compressed_main
    assert private_key.wif(compressed=True, network=Network.MAINNET) == priv_key_wif_compressed_main
    assert private_key.wif(compressed=False, network=Network.MAINNET) == priv_key_wif_uncompressed_main
    assert private_key.wif(compressed=True, network=Network.TESTNET) == priv_key_wif_compressed_test
    assert private_key.wif(compressed=False, network=Network.TESTNET) == priv_key_wif_uncompressed_test

    assert PrivateKey(private_key_bytes) == private_key
    assert PrivateKey(priv_key_wif_compressed_main) == private_key
    assert PrivateKey(priv_key_wif_uncompressed_main) == private_key
    assert PrivateKey(priv_key_wif_compressed_test) == private_key
    assert PrivateKey(priv_key_wif_uncompressed_test) == private_key

    assert PrivateKey(private_key_bytes).wif() == priv_key_wif_compressed_main
    assert PrivateKey(private_key_bytes).address() == address_compressed_main

    assert PrivateKey(priv_key_wif_compressed_main).wif() == priv_key_wif_compressed_main
    assert PrivateKey(priv_key_wif_compressed_main).address() == address_compressed_main

    assert PrivateKey(priv_key_wif_uncompressed_main).wif() == priv_key_wif_uncompressed_main
    assert PrivateKey(priv_key_wif_uncompressed_main).address() == address_uncompressed_main

    assert PrivateKey(priv_key_wif_compressed_test).wif() == priv_key_wif_compressed_test
    assert PrivateKey(priv_key_wif_compressed_test).address() == address_compressed_test

    assert PrivateKey(priv_key_wif_uncompressed_test).wif() == priv_key_wif_uncompressed_test
    assert PrivateKey(priv_key_wif_uncompressed_test).address() == address_uncompressed_test

    with pytest.raises(TypeError, match=r'unsupported private key type'):
        # noinspection PyTypeChecker
        PrivateKey(1.23)


def test_verify():
    digest1 = bytes.fromhex(
        '01000000'
        'ae4b0ed7fb33ec9d5c567520f8cf5f688207f28d5c2f2225c5fe62f7f17c0a25'
        '3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044'
        '48dd1f8e77b4a6a75e9b0d0908b25f56b8c98ce37d1fb5ada534d49d0957bcd201000000'
        '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
        'e803000000000000'
        'ffffffff'
        '048129b26f1d89828c88cdcd472f8f20927822ab7a3d6532cb921c4019f51301'
        '00000000'
        '41000000'
    )
    digest2 = bytes.fromhex(
        '01000000'
        'ee2851915c957b7187967dabb54f32c00964c689285d3b73e7b2b92e30723c88'
        '752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad'
        '48dd1f8e77b4a6a75e9b0d0908b25f56b8c98ce37d1fb5ada534d49d0957bcd202000000'
        '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ace'
        '803000000000000'
        'ffffffff'
        'd67a44dde8ee744b7d73b50a3b3a887cb3321d6e16025273f760046c35a265fd'
        '00000000'
        '41000000'
    )
    digest3 = bytes.fromhex(
        '01000000'
        'ee2851915c957b7187967dabb54f32c00964c689285d3b73e7b2b92e30723c88'
        '752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad'
        'e4c1a33b3a7ca18ef1d6030c6ec222902195f186cb864e09bc1db08b3ea5c1fc00000000'
        '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ace'
        '803000000000000'
        'ffffffff'
        'd67a44dde8ee744b7d73b50a3b3a887cb3321d6e16025273f760046c35a265fd'
        '00000000'
        '41000000'
    )

    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    der: bytes = bytes.fromhex('304402207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a'
                               '022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5')
    assert private_key.verify(der, digest1)

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    der: bytes = bytes.fromhex('3043022053b1f5a28a011c60614401eeef88e49c676a098ce36d95ded1b42667f40efa37'
                               '021f4de6703f8c74b0ce5dad617c00d1fb99580beb7972bf681e7215911c3648de')
    assert private_key.verify(der, digest2)
    der: bytes = bytes.fromhex('3045022100b9f293781ae1e269591df779dbadb41b9971d325d7b8f83d883fb55f2cb3ff76'
                               '02202fe1e822628d85b0f52966602d0e153be411980d54884fa48a41d6fc32b4e9f5')
    assert private_key.verify(der, digest3)


def test_sign():
    # ecdsa
    message: bytes = b'hello world'
    der: bytes = private_key.sign(message)
    vk = ecdsa.VerifyingKey.from_string(public_key.serialize(), curve=ecdsa.SECP256k1)
    assert vk.verify(signature=der, data=sha256(message), hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der)

    # recoverable ecdsa
    text = 'hello world'
    address, signature = private_key.sign_text(text)
    assert verify_signed_text(text, address, signature)

    message: bytes = text_digest(text)
    serialized_recoverable, _ = unstringify_ecdsa_recoverable(signature)
    assert private_key.verify_recoverable(serialized_recoverable, message)

    address, signature = PrivateKey('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U').sign_text(text)
    assert verify_signed_text(text, address, signature)


def test_ecdh():
    alice, bob = PrivateKey(), PrivateKey()
    assert alice.ecdh_key(bob.public_key()) == bob.ecdh_key(alice.public_key())
    ephemeral = PrivateKey()
    assert alice.public_key().ecdh_key(ephemeral) == alice.ecdh_key(ephemeral.public_key())


def test_encryption():
    plain = 'hello world'
    encrypted = ('QklFMQPkjNG3xxnfRv7oUDjUYPH2VN3VFrcglCcwmeYpJpsjRKnfl/XsS+dOg'
                 'ocRV6JKVHkfUZAKIHDo7vwxjv/BPkV5EA2Dl4RJ6d/jpWwgGdFBYA==')
    assert private_key.decrypt_text(encrypted) == plain
    assert private_key.decrypt_text(public_key.encrypt_text(plain)) == plain
