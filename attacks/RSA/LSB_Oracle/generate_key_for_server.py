from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from mysecrets import rsa_key_pwd, rsa_msg

key = RSA.generate(2048)


f = open('../more/myserverkey.pem', 'wb')
f.write(key.export_key(format = 'PEM',passphrase=rsa_key_pwd,pkcs=8))
f.close()

f = open('../more/public_serverkey.pem', 'wb')
f.write(key.publickey().export_key(format = 'PEM'))
f.close()

cipher_public = PKCS1_OAEP.new(key.publickey())
ciphertext = cipher_public.encrypt(rsa_msg.encode())


f = open('../more/encrypted_msg.rsa', 'wb')
f.write(ciphertext)
f.close()
