from Crypto.Cipher import ChaCha20


####
from Crypto.Random import get_random_bytes

plaintext = b'This is a string where there are numbers 123456. Bye!'

# sender
#encrypt with ChaCha20
key = get_random_bytes(32)
cipher = ChaCha20.new(key = key) #nonce
ciphertext = cipher.encrypt(plaintext) #bytes: unmodifiable

# sent the ciphertext

#################
# attacker side (with some helps) : MitM
index = plaintext.index(b'1')
print(index)
print(plaintext[index])

new_value = b'2'
print(new_value)
print(ord(new_value))
#'1' 49
#'2' 50 --> last two bits will change

#build the mask
# a XOR b = c --> a XOR c = b

#build an editable byte array and update it with the mask
# do not use XOR with bytes
mask = plaintext[index] ^ ord(new_value)
print(mask) # 0011
cipher_array = bytearray(ciphertext)
cipher_array[index] = cipher_array[index] ^ mask

print(cipher_array[index])
print(ciphertext[index])

print("          "+str(ciphertext))
print(cipher_array)

# MitM sends this new ciphertext to the recipient

####
#check by decrpytion
cipher_dec = ChaCha20.new(key= key, nonce=cipher.nonce)
print(cipher_dec.decrypt(cipher_array))
