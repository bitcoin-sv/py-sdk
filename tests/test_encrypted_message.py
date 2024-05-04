import pytest

from bsv.encrypted_message import aes_gcm_encrypt, aes_gcm_decrypt, encrypt, decrypt
from bsv.keys import PrivateKey
from bsv.utils import randbytes


def test_aes_gcm():
    key = randbytes(32)
    message = 'hello world'.encode('utf-8')
    encrypted = aes_gcm_encrypt(key, message)
    decrypted = aes_gcm_decrypt(key, encrypted)
    assert decrypted == message


def test_brc78():
    message = 'hello world'.encode('utf-8')
    sender_priv, recipient_priv = PrivateKey(), PrivateKey()
    encrypted = encrypt(message, sender_priv, recipient_priv.public_key())
    decrypted = decrypt(encrypted, recipient_priv)
    assert decrypted == message

    with pytest.raises(ValueError, match=r'message version mismatch'):
        decrypt(encrypted[1:], PrivateKey())
    with pytest.raises(ValueError, match=r'recipient public key mismatch'):
        decrypt(encrypted, PrivateKey())
    with pytest.raises(ValueError, match=r'failed to decrypt message'):
        decrypt(encrypted[:-1], recipient_priv)
