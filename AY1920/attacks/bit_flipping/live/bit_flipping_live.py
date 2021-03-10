from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'This is the message to encrypt and this a number to change 12345. Bye!'

# generate random key and nonce
key = get_random_bytes(32)
nonce = get_random_bytes(12)

# create the stream cipher object and ecnrypt the plaintext
cipher = ChaCha20.new(key=key,nonce=nonce)

ciphertext = cipher.encrypt(plaintext)

##############333
# here we are the attackers

#generate the bit flipping mask
print(plaintext.index(b'1'))
print(chr(plaintext[59]))

index = plaintext.index(b'1')

# plaintext is bytes -> immutable
ciphertext_array = bytearray(ciphertext) #this can be manipulated
print(chr(ciphertext_array[index]))

# build the mask  a ^ b = c --> c ^ b = a
old_byte = chr(plaintext[index])
new_byte = '9'
mask = ord(old_byte) ^ ord(new_byte)
print(old_byte)
print(new_byte)
print(mask)

ciphertext_array[index] = ciphertext_array[index] ^ mask
print(ciphertext_array[index])

#################3333
# the modified ciphertext is manipulated by the recipient
cipher_dec = ChaCha20.new(key=key, nonce=nonce)
print(cipher_dec.decrypt(ciphertext_array))











