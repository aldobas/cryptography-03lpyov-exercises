from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

N = 1024

#generate keypair
keypair = RSA.generate(N)
print(keypair.e)
print(keypair.d)
print(keypair.n)
print(keypair.p)
print(keypair.q)

#export to file
export_key_material = keypair.export_key(format = 'PEM',pkcs=8, passphrase = 'verystrongpassphrase_2')
print(export_key_material)

f = open("myrsakey.pem",'wb')
f.write(export_key_material)
f.close()

##############3
#simulate import
fread = open("myrsakey.pem",'r')
keypair_from_file = RSA.import_key(fread.read(), passphrase = 'verystrongpassphrase_2')
print(keypair_from_file.e)
print(keypair_from_file.d)
print(keypair_from_file.n)
print(keypair_from_file.p)
print(keypair_from_file.q)

# data --> ASN.1 --> binary data using DER (binary objct)
# encode with Base64(file.der) --> file.pem



#extract public key
public_key = keypair.public_key()




####################
# encrypt data = confidentiality = OAEP
message = b'This is another secret message'
# Alice
rsa_encrypter = PKCS1_OAEP.new(public_key)
rsa_enc_message = rsa_encrypter.encrypt(message)

# Bob: rsa_enc_message
rsa_decrypter = PKCS1_OAEP.new(keypair)
dec_message = rsa_decrypter.decrypt(rsa_enc_message)
print(dec_message)
print(dec_message.decode())

###############################3
# digital signatures = authc+int = PSS
sig_generator = pss.new(keypair)

hash_generator = SHA256.new(message)
# hash_generator.digest()
signature = sig_generator.sign(hash_generator) # not the digest but the class wrapping the generation
print(signature)

#############33
# we have the public key
# we have the signature
# we have the message
hash_verifier = SHA256.new(message)
sig_verifier = pss.new(public_key)

try:
    sig_verifier.verify(hash_verifier,signature)
    print("Signature OK")
except (ValueError,TypeError):
    print("Signature verification failure")

#manipulated
sig2 = bytearray(signature)
sig2[0] = 1

hash_verifier2 = SHA256.new(message)
sig_verifier = pss.new(public_key)

try:
    sig_verifier.verify(hash_verifier2,sig2)
    print("Signature OK")
except (ValueError,TypeError):
    print("Signature verification failure")
