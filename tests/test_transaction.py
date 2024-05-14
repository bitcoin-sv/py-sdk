import pytest

from bsv.constants import SIGHASH, Network
from bsv.hash import hash256
from bsv.keys import PrivateKey
from bsv.script.script import Script
from bsv.script.type import P2PKH, P2PK
from bsv.service.service import WhatsOnChain
from bsv.transaction import TxInput, TxOutput, Transaction, TxBytesIO
from bsv.unspent import Unspent
from bsv.utils import encode_pushdata

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


def test_output():
    assert TxOutput(['123', '456']).locking_script == Script('006a' + '03313233' + '03343536')

    with pytest.raises(TypeError, match=r'unsupported transaction output type'):
        # noinspection PyTypeChecker
        TxOutput(1)


def test_digest():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    # https://whatsonchain.com/tx/4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    expected_digest = [digest1]
    t: Transaction = Transaction()
    t.add_input(Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=1, value=1000, address=address))
    t.add_output(TxOutput(out='1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw', value=800))
    assert t.digests() == expected_digest

    # https://whatsonchain.com/tx/c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    expected_digest = [digest2, digest3]
    t: Transaction = Transaction()
    t.add_inputs([
        Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=2, value=1000, address=address),
        Unspent(txid='fcc1a53e8bb01dbc094e86cb86f195219022c26e0c03d6f18ea17c3a3ba3c1e4', vout=0, value=1000, address=address),
    ])
    t.add_output(TxOutput(out='18CgRLx9hFZqDZv75J5kED7ANnDriwvpi1', value=1700))
    assert t.digest(0) == expected_digest[0]
    assert t.digest(1) == expected_digest[1]


def test_transaction():
    address = '1AfxgwYJrBgriZDLryfyKuSdBsi59jeBX9'
    t = Transaction()
    t.add_input(Unspent(txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', vout=1, value=1000, address=address))
    t.add_output(TxOutput(out='1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw', value=800))

    signature = bytes.fromhex('3044'
                              '02207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a'
                              '022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5')
    sighash = bytes.fromhex('41')
    public_key = bytes.fromhex('02e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789')
    t.inputs[0].unlocking_script = Script(encode_pushdata(signature + sighash) + encode_pushdata(public_key))

    assert t.txid() == '4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb'
    assert t.fee() == 200
    assert t.byte_length() == 191

    t.inputs[0].sighash = SIGHASH.NONE_ANYONECANPAY_FORKID
    assert t.digest(0) == t._digest(t.inputs[0], b'\x00' * 32, b'\x00' * 32, b'\x00' * 32)
    t.inputs[0].sighash = SIGHASH.SINGLE_ANYONECANPAY_FORKID
    assert t.digest(0) == t._digest(t.inputs[0], b'\x00' * 32, b'\x00' * 32, hash256(t.outputs[0].serialize()))

    t.inputs[0].private_keys = [PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')]
    assert t.estimated_fee() == 96

    t.outputs[0].value = 100
    t.add_change(address)
    # 1-2 transaction 226 bytes --> fee 113 satoshi --> 787 left
    assert len(t.outputs) == 2
    assert t.outputs[1].locking_script == P2PKH.locking(address)
    assert t.outputs[1].value == 787

    t.outputs.pop()
    t.add_change()
    assert len(t.outputs) == 2
    assert t.outputs[1].locking_script == P2PKH.locking(address)
    assert t.outputs[1].value == 787


def test_transaction_bytes_io():
    io = TxBytesIO(bytes.fromhex('0011223344556677889912fd1234fe12345678ff1234567890abcdef00112233'))

    assert io.read_bytes(4) == bytes.fromhex('00112233')
    assert io.read_int(1) == int.from_bytes(bytes.fromhex('44'), 'little')
    assert io.read_int(2) == int.from_bytes(bytes.fromhex('5566'), 'little')
    assert io.read_int(3, 'big') == int.from_bytes(bytes.fromhex('778899'), 'big')
    assert io.read_varint() == int.from_bytes(bytes.fromhex('12'), 'little')
    assert io.read_varint() == int.from_bytes(bytes.fromhex('1234'), 'little')
    assert io.read_varint() == int.from_bytes(bytes.fromhex('12345678'), 'little')
    assert io.read_varint() == int.from_bytes(bytes.fromhex('1234567890abcdef'), 'little')

    assert io.read_bytes(0) == b''
    assert io.read_bytes() == bytes.fromhex('00112233')
    assert io.read_bytes() == b''
    assert io.read_bytes(1) == b''

    with pytest.raises(AssertionError):
        io.read_int(1)
    with pytest.raises(AssertionError):
        io.read_varint()


def test_from_hex():
    assert TxInput.from_hex('') is None
    tx_in = TxInput.from_hex('0011' * 16 + '00112233' + '00' + '00112233')
    assert tx_in.txid == '1100' * 16
    assert tx_in.vout == 0x33221100
    assert tx_in.unlocking_script == Script()
    assert tx_in.sequence == 0x33221100

    assert TxOutput.from_hex('') is None
    assert Transaction.from_hex('') is None

    t = Transaction.from_hex(
        '01000000' +
        '03' +
        '7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08' +
        '01000000' +
        '6b' +
        '483045' +
        '0221008b6f070f73242c7c8c654f493dd441d46dc7b2365c8e9e4c62732da0fb535c58' +
        '02204b96edfb934d08ad0cfaa9bf75887bd8541498fbe19189d45683dcbd0785d0df' +
        '41' +
        '2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789' +
        'ffffffff' +
        '7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08' +
        '03000000' +
        '6a' +
        '473044' +
        '0220501dae7c51c6e5cb0f12a635ccbc61e283cb2e838d624d7df7f1ba1b0ab2087b' +
        '02207f67f3883735464f6067357c901fc1b8ddf8bf8695b54b2790d6a0106acf2340' +
        '41' +
        '2102e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd789' +
        'ffffffff' +
        '7a7b64d59a072867d7453b2eb67e0fb883af0f435cbbeffc2bb5a4b13e3f6e08' +
        '02000000' +
        '8b' +
        '483045' +
        '022100b04829882018f7488508cb8587612fb017584ffc2b4d22e4300b95178be642a3' +
        '02207937cb643eef061b53704144148bec25645fbbaf4eedd5586ad9b018d4f6c9d441' +
        '41' +
        '04' +
        'e46dcd7991e5a4bd642739249b0158312e1aee56a60fd1bf622172ffe65bd78997693d32c540ac253de7a3dc73f7e4ba7b38d2dc1ecc8e07920b496fb107d6b2' +
        'ffffffff' +
        '02' +
        '0a1a000000000000' +
        '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac' +
        '05ea1c0000000000' +
        '1976a9146a176cd51593e00542b8e1958b7da2be97452d0588ac' +
        '00000000'
    )
    assert t.txid() == 'e8c6b26f26d90e9cf035762a91479635a75eff2b3b2845663ed72a2397acdfd2'


def test_parse_outputs():
    k = PrivateKey()
    fake_unspent = Unspent(txid='00' * 32, vout=0, value=3000, private_keys=[k])

    t = Transaction().add_input(fake_unspent)
    # OP_RETURN
    out0 = TxOutput(['hello', 'world'])
    # P2PKH
    out1 = TxOutput(k.address(), 1000)
    # P2PK
    out2 = TxOutput(P2PK.locking(k.public_key().serialize()), 1000, P2PK())

    t.add_outputs([out0, out1, out2]).sign()
    _unspent1 = Unspent(txid=t.txid(), vout=1, value=1000)
    _unspent2 = Unspent(txid=t.txid(), vout=2, value=1000)

    u0 = t.to_unspent(0)
    assert u0 is None

    u1 = t.to_unspent(1, height=2000)
    assert u1 == _unspent1 and u1.script_type == P2PKH() and u1.height == 2000 and u1.private_keys == []

    u2 = t.to_unspent(2, private_keys=[k])
    assert u2 == _unspent2 and u2.script_type == P2PK() and u2.height == -1 and u2.private_keys == [k]

    assert t.to_unspents([0]) == []

    us1 = t.to_unspents([1], [{'height': 2000}])
    assert us1 == [_unspent1] and us1[0].script_type == P2PKH() and us1[0].height == 2000 and us1[0].private_keys == []

    us21 = t.to_unspents([2, 1], [{'height': 2000}])
    assert us21 == [_unspent2, _unspent1]
    assert us21[0].script_type == P2PK() and us21[0].height == 2000 and us21[0].private_keys == []
    assert us21[1].script_type == P2PKH() and us21[1].height == -1 and us21[1].private_keys == []

    us012 = t.to_unspents(args=[{}, {'height': 2000}, {'private_keys': [k]}])
    assert us012 == [_unspent1, _unspent2]
    assert us012[0].script_type == P2PKH() and us012[0].height == 2000 and us012[0].private_keys == []
    assert us012[1].script_type == P2PK() and us012[1].height == -1 and us012[1].private_keys == [k]


def test_chain_provider():
    t = Transaction()
    assert t.network is None
    assert t.provider is None

    t = Transaction(network=Network.TESTNET)
    assert t.network == Network.TESTNET
    assert t.provider is None

    t = Transaction(provider=WhatsOnChain())
    assert t.network == Network.MAINNET
    assert isinstance(t.provider, WhatsOnChain)
    assert t.provider.network == Network.MAINNET

    t = Transaction(network=Network.TESTNET, provider=WhatsOnChain())
    assert t.network == Network.MAINNET
    assert isinstance(t.provider, WhatsOnChain)
    assert t.provider.network == Network.MAINNET


def test_estimated_byte_length():
    _in = TxInput()
    _in.script_type = P2PKH()
    _in.value = 2000

    _out = TxOutput(PrivateKey().address(), 1000)

    t = Transaction().add_input(_in).add_output(_out)

    with pytest.raises(ValueError, match=r"can't estimate unlocking byte length"):
        t.estimated_byte_length()

    _in.private_keys = [PrivateKey()]
    assert t.estimated_byte_length() == 192

    _in.unlocking_script = b''
    assert t.estimated_byte_length() == 85
    assert t.estimated_byte_length() == t.byte_length()
