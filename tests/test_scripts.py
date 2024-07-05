import pytest

from bsv.constants import SIGHASH, OpCode
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.type import P2PKH, OpReturn, P2PK, BareMultisig
from bsv.utils import address_to_public_key_hash, encode_pushdata, encode_int


def test_script():
    locking_script = '76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
    assert Script(locking_script) == Script(bytes.fromhex(locking_script))
    assert Script(locking_script).hex() == locking_script
    assert Script(locking_script).size_varint() == b'\x19'

    assert Script().serialize() == b''
    assert Script().hex() == ''
    assert Script().byte_length() == 0

    with pytest.raises(TypeError, match=r'unsupported script type'):
        # noinspection PyTypeChecker
        Script(1)


def test_p2pkh():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    locking_script = '76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'
    assert P2PKH(address).locking() == Script(locking_script)
    assert P2PKH(address_to_public_key_hash(address)).locking() == Script(locking_script)

    with pytest.raises(TypeError, match=r"unsupported type to parse P2PKH locking script"):
        # noinspection PyTypeChecker
        P2PKH(1)

    key_compressed = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
    key_uncompressed = PrivateKey('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U')
    assert P2PKH(address).estimated_unlocking_byte_length(private_keys=[key_compressed]) == 107
    assert P2PKH(address).estimated_unlocking_byte_length(private_keys=[key_uncompressed]) == 139

    payload = {'signatures': [b'\x00'], 'private_keys': [key_compressed], 'sighash': SIGHASH.ALL_FORKID}
    assert P2PKH(address).unlocking(**payload).hex() == '020041' + '21' + key_compressed.public_key().hex()


def test_op_return():
    assert OpReturn(['0']).locking() == Script('006a0130')
    assert OpReturn(['0' * 0x4b]).locking() == Script('006a' + '4b' + '30' * 0x4b)
    assert OpReturn(['0' * 0x4c]).locking() == Script('006a' + '4c4c' + '30' * 0x4c)
    assert OpReturn(['0' * 0x0100]).locking() == Script('006a' + '4d0001' + '30' * 0x0100)
    assert OpReturn([b'\x31\x32', '345']).locking() == Script('006a' + '023132' + '03333435')

    with pytest.raises(TypeError, match=r"unsupported type to parse OP_RETURN locking script"):
        # noinspection PyTypeChecker
        OpReturn([1]).locking()


def test_p2pk():
    public_key = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9').public_key()
    assert P2PK(public_key.hex()).locking() == P2PK(public_key.serialize()).locking()

    with pytest.raises(TypeError, match=r"unsupported type to parse P2PK locking script"):
        # noinspection PyTypeChecker
        P2PK(1)

    payload = {'signatures': [b'\x00'], 'sighash': SIGHASH.ALL_FORKID}
    assert P2PK(public_key.hex()).unlocking(**payload).hex() == '020041'


def test_bare_multisig():
    pk1, pk2, pk3 = PrivateKey().public_key(), PrivateKey().public_key(), PrivateKey().public_key()
    pks = [pk1.hex(), pk2.serialize(compressed=False), pk3.serialize()]
    encoded_pks = b''.join([encode_pushdata(pk if isinstance(pk, bytes) else bytes.fromhex(pk)) for pk in pks])
    expected_locking = encode_int(2) + encoded_pks + encode_int(3) + OpCode.OP_CHECKMULTISIG
    assert BareMultisig(pks, 2).locking().serialize() == expected_locking

    payload = {'signatures': [b'\x00', b'\x01'], 'sighash': SIGHASH.ALL_FORKID}
    assert BareMultisig(pks, 2).unlocking(**payload).hex() == '00' + '020041' + '020141'
