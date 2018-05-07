
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

message = b'I wonder if it will work'
key = RSA.importKey(open('private.pem').read())
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(message)
print(ciphertext)
