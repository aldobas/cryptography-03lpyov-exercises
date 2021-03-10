from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'This is the message to encrypt and this a number to change 12345. Bye!'

# generate random key and nonce
key = get_random_bytes(32)
nonce = get_random_bytes(12)

# create the stream cipher object and ecnrypt the plaintext
cipher = ChaCha20.new(key=key,nonce=nonce)

ciphertext = cipher.encrypt(plaintext)

# find the position  of the byte  to flip
print(plaintext.index(b'1'))
print(chr(plaintext[59]))


index = plaintext.index(b'1')

# from bytes to bytearray (bytes are immutable)
ciphertext_array = bytearray(ciphertext)
print(ciphertext_array[index])

# find the mask
old_byte = chr(plaintext[index])
new_byte = '2'
print(ord(old_byte))
print(ord(new_byte))
print(ord(old_byte) ^ ord(new_byte))

# change the ciphertext
ciphertext_array[index] = ciphertext[index] ^ ord(old_byte) ^ ord(new_byte) # ord(old_byte) ^ ord(new_byte) is the mask
print(ciphertext_array[index])

# only done at the recipient!!!!
# check that the decryption has changed the value
cipher_dec = ChaCha20.new(key=key,nonce=nonce)
print(cipher_dec.decrypt(ciphertext_array))
