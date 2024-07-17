import pytest

from bsv.constants import OpCode
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.type import P2PKH, OpReturn, P2PK, BareMultisig
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
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
    assert P2PKH().locking(address) == Script(locking_script)
    assert P2PKH().locking(address_to_public_key_hash(address)) == Script(locking_script)

    with pytest.raises(TypeError, match=r"unsupported type to parse P2PKH locking script"):
        # noinspection PyTypeChecker
        P2PKH().locking(1)

    key_compressed = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
    key_uncompressed = PrivateKey('5KiANv9EHEU4o9oLzZ6A7z4xJJ3uvfK2RLEubBtTz1fSwAbpJ2U')
    assert P2PKH().unlocking(key_compressed).estimated_unlocking_byte_length() == 107
    assert P2PKH().unlocking(key_uncompressed).estimated_unlocking_byte_length() == 139

    source_tx = Transaction(
        [],
        [
            TransactionOutput(
                locking_script=Script(locking_script),
                value=1000
            )
        ]
    )
    tx = Transaction([
        TransactionInput(
            source_transaction=source_tx,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlocking(key_compressed)
        )
    ], [])
    tx.add_change(address)

    unlocking_script = P2PKH().unlocking(key_compressed).sign(tx, 0)
    assert isinstance(unlocking_script, Script)
    assert unlocking_script.byte_length() in [106, 107]


def test_op_return():
    assert OpReturn().locking(['0']) == Script('006a0130')
    assert OpReturn().locking(['0' * 0x4b]) == Script('006a' + '4b' + '30' * 0x4b)
    assert OpReturn().locking(['0' * 0x4c]) == Script('006a' + '4c4c' + '30' * 0x4c)
    assert OpReturn().locking(['0' * 0x0100]) == Script('006a' + '4d0001' + '30' * 0x0100)
    assert OpReturn().locking([b'\x31\x32', '345']) == Script('006a' + '023132' + '03333435')

    with pytest.raises(TypeError, match=r"unsupported type to parse OP_RETURN locking script"):
        # noinspection PyTypeChecker
        OpReturn().locking([1])


def test_p2pk():
    private_key = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
    public_key = private_key.public_key()
    assert P2PK().locking(public_key.hex()) == P2PK().locking(public_key.serialize())

    with pytest.raises(TypeError, match=r"unsupported type to parse P2PK locking script"):
        # noinspection PyTypeChecker
        P2PK().locking(1)

    source_tx = Transaction(
        [],
        [
            TransactionOutput(
                locking_script=P2PK().locking(public_key.hex()),
                value=1000
            )
        ]
    )
    tx = Transaction([
        TransactionInput(
            source_transaction=source_tx,
            source_output_index=0,
            unlocking_script_template=P2PK().unlocking(private_key)
        )
    ], [])
    tx.add_change(public_key.address())

    unlocking_script = P2PK().unlocking(private_key).sign(tx, 0)
    assert isinstance(unlocking_script, Script)
    assert unlocking_script.byte_length() in [72, 73]


def test_bare_multisig():
    privs = [PrivateKey(), PrivateKey(), PrivateKey()]
    pubs = [privs[0].public_key().hex(), privs[1].public_key().serialize(compressed=False),
            privs[2].public_key().serialize()]
    encoded_pks = b''.join([encode_pushdata(pk if isinstance(pk, bytes) else bytes.fromhex(pk)) for pk in pubs])
    expected_locking = encode_int(2) + encoded_pks + encode_int(3) + OpCode.OP_CHECKMULTISIG
    assert BareMultisig().locking(pubs, 2).serialize() == expected_locking

    source_tx = Transaction(
        [],
        [
            TransactionOutput(
                locking_script=BareMultisig().locking(pubs, 2),
                value=1000
            )
        ]
    )
    tx = Transaction([
        TransactionInput(
            source_transaction=source_tx,
            source_output_index=0,
            unlocking_script_template=BareMultisig().unlocking(privs)
        )
    ], [])
    tx.add_change('1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9')

    unlocking_script = BareMultisig().unlocking(privs).sign(tx, 0)
    assert isinstance(unlocking_script, Script)
    print(unlocking_script.byte_length())
    assert unlocking_script.byte_length() > 210


def test_is_push_only():
    assert Script('00').is_push_only()  # OP_0
    assert not Script('006a').is_push_only()  # OP_0 OP_RETURN
    assert Script('4c051010101010').is_push_only()

    # like bitcoind, we regard OP_RESERVED as being "push only"
    assert Script('50').is_push_only()  # OP_RESERVED


def test_to_asm():
    assert Script('000301020300').to_asm() == 'OP_0 010203 OP_0'

    asm = 'OP_DUP OP_HASH160 f4c03610e60ad15100929cc23da2f3a799af1725 OP_EQUALVERIFY OP_CHECKSIG'
    assert Script('76a914f4c03610e60ad15100929cc23da2f3a799af172588ac').to_asm() == asm


def test_from_asm():
    assert Script.from_asm('OP_0 3 010203 OP_0').to_asm() == 'OP_0 03 010203 OP_0'

    asms = [
        '',
        'OP_0 010203 OP_0',
        'OP_SHA256 8cc17e2a2b10e1da145488458a6edec4a1fdb1921c2d5ccbc96aa0ed31b4d5f8 OP_EQUALVERIFY',
    ]
    for asm in asms:
        assert Script.from_asm(asm).to_asm() == asm

    _asm_pushdata(220)
    _asm_pushdata(1024)
    _asm_pushdata(pow(2, 17))

    asms = [
        'OP_FALSE',
        'OP_0',
        '0',
    ]
    for asm in asms:
        assert Script.from_asm(asm).to_asm() == 'OP_0'

    asms = [
        'OP_1NEGATE',
        '-1',
    ]
    for asm in asms:
        assert Script.from_asm(asm).to_asm() == 'OP_1NEGATE'


def _asm_pushdata(byte_length: int):
    octets = b'\x00' * byte_length
    asm = 'OP_RETURN ' + octets.hex()
    assert Script.from_asm(asm).to_asm() == asm


def test_find_and_delete():
    source = Script.from_asm('OP_RETURN f0f0')
    assert Script.find_and_delete(source, Script.from_asm('f0f0')).to_asm() == 'OP_RETURN'
