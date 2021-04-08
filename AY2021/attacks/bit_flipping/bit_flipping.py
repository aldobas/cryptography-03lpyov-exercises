from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

######################################
# the sender
plaintext = b'This is the message to encrypt and this a number to change 12345. Bye!'
# generate random key and nonce
key = get_random_bytes(32)
nonce = get_random_bytes(12)
# create the stream cipher object and ecnrypt the plaintext
cipher = ChaCha20.new(key=key,nonce=nonce)

ciphertext = cipher.encrypt(plaintext)



###############
# ATTACKER: only knows the ciphertext

# find the position of the byte to flip (e.g., by trial and error)
index = plaintext.index(b'1')


# from bytes to bytearray (bytes are immutable)
ciphertext_array = bytearray(ciphertext)
print(ciphertext_array[index])


new_byte = '2'
print(ord(new_byte)) #its ASCII code
print(plaintext[index])

print(plaintext[index] ^ ord(new_byte))

# change the ciphertext
ciphertext_array[index] = ciphertext[index] ^ plaintext[index] ^ ord(new_byte)
print(ciphertext_array[index])

# only done at the recipient!!!!
# check that the decryption has changed the value
cipher_dec = ChaCha20.new(key=key,nonce=nonce)
print(cipher_dec.decrypt(ciphertext_array))
