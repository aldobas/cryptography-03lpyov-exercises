from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP


#generate a new private key
key = RSA.generate(2048) #e=65537 by default
print(key.export_key(format = 'PEM',pkcs=8))

# save in PEM into a file
f = open('mykey.pem','wb')
f.write(key.export_key(format = 'PEM',passphrase='longpassphrasehere',pkcs=8))
f.close()

#open back the private key
f = open('mykey.pem','r')
key = RSA.import_key(f.read(),passphrase='longpassphrasehere')

#print the parameters
print(key.n)
print(key.e)
print(key.d)
print(key.p)
print(key.q)


#create a given RSA key when you know all the parameters
key2 = RSA.construct((key.n,key.e,key.d,key.p,key.q), consistency_check=True)
print(key2.n)
print(key2.e)
print(key2.d)
print(key2.p)
print(key2.q)

#exception, wrong parameters uncomment to check
# key3 = RSA.construct((key.n,key.e,key.d,key.p,5), consistency_check=True)


#let's extract the public key
public_key = key.publickey()
print(public_key)
# public_key.export_key()


############################################################################################
# signatures
############################################################################################


message = b'This is the message to be signed'

# manually compute the hash
h = SHA256.new(message)
#sign the digest with the PSS signature object
signature = pss.new(key).sign(h)


#here we are at the verifier, he obtained the public key in a trustworthy manner
# and the message in a normal channel
h = SHA256.new(message)
#verify  the digest with the PSS signature object: public key
verifier = pss.new(public_key)
try:
    verifier.verify(h, signature)
    print("The signature is authentic.")
except (ValueError, TypeError):
    print("The signature is not authentic.")



############################################################################################
# encryption
############################################################################################

message = b'This is a secret message'

# cipher object implementing OAEP: encrypt with public key
cipher_public = PKCS1_OAEP.new(public_key)
ciphertext = cipher_public.encrypt(message)

# cipher object implementing OAEP: decrypt with public key
cipher_private = PKCS1_OAEP.new(key)
message_dec = cipher_private.decrypt(ciphertext)
print(message_dec)
