from bsv import PrivateKey, verify_signed_text

private_key = PrivateKey('L5agPjZKceSTkhqZF2dmFptT5LFrbr6ZGPvP7u4A6dvhTrr71WZ9')
text = 'hello world'

# sign arbitrary text with bitcoin private key
address, signature = private_key.sign_text(text)

# verify https://www.verifybitcoinmessage.com/
print(address, signature)

# verify
print(verify_signed_text(text, address, signature))
