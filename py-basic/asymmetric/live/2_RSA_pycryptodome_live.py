from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

#generate an RSA private key
key = RSA.generate(2048)
print(key.export_key(format = 'PEM', pkcs=8))


f = open('myrsakey.pem','wb')
f.write(key.export_key(format = 'PEM', pkcs=8,passphrase='longlongpassphrasehere'))
f.close()

f = open('myrsakey.pem','r')
key = RSA.import_key(f.read(),passphrase='longlongpassphrasehere')
f.close()

print(key.p)
print(key.q)
print(key.n)
print(key.e)
print(key.d)


key2 = RSA.construct((key.n,key.e,key.d,key.p,key.q),consistency_check=True)
print(key2.p)
print(key2.q)
print(key2.n)
print(key2.e)
print(key2.d)


# key3 = RSA.construct((key.n,key.e,key.d,key.p,5),consistency_check=True)


# extract the public key
public_key = key.publickey()


###################################################
# SIGNATURES
###################################################

message = b'This is the message to sign'

#manually compute the digest
h = SHA256.new(message)
# sign with pss object
signer = pss.new(key)
signature = signer.sign(h)


###########3
# on the verifier side
# received signature and message
messagev = message
signaturev = signature

hv = SHA256.new(messagev)
verifier = pss.new(public_key)
try:
    verifier.verify(hv,signaturev)
    print("OK authentic")
except (ValueError,TypeError):
    print("No signature error")


#########################################33
# encryption

message = b'This is the message to encrypt'

#encrypt with public key
cipher_public = PKCS1_OAEP.new(public_key)
ciphertext = cipher_public.encrypt(message)

#decrypt = encrypt with private key
cipher_private = PKCS1_OAEP.new(key)
message_dec = cipher_private.decrypt(ciphertext)
print(message_dec)
