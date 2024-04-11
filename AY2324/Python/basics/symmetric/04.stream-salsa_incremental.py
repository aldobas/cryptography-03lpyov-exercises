from Crypto.Cipher import Salsa20

# these are bytes
key = b'deadbeefdeadbeef'
cipher = Salsa20.new(key)

#incremental encryption with a stream cipher
ciphertext =  cipher.encrypt(b'The first part of the secret message. ')
ciphertext += cipher.encrypt(b'The second part of the message.')
#also the ciphertext is made of bytes

#print the nonce you will have to share
nonce = cipher.nonce
print(nonce)

# check: decryption works
cipher2 = Salsa20.new(key,nonce)
plaintext = cipher2.decrypt(ciphertext)
print("Decrypted = "+plaintext.decode("utf-8"))

