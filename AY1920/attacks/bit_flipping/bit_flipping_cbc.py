from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# simulate the use of a session cookie that contains
# username = ???, admin = 0



plaintext = b'username = aldo,admin=0'
print(plaintext)
print(len(plaintext))

key = get_random_bytes(32)
iv = get_random_bytes(16)
cipher = AES.new(key,AES.MODE_CBC,iv)

print(key)
print(iv)

ciphertext = cipher.encrypt(pad(plaintext,AES.block_size))

old_block = pad(b'admin=0',AES.block_size)
print(old_block)
new_block = pad(b'admin=1',AES.block_size)
print(new_block)
delta = bytes(a ^ b for (a, b) in zip(old_block,new_block))
print(delta)

print(len(ciphertext))
ciphertext_array = bytearray(ciphertext)
for i in range(0,16):
    ciphertext_array[i]^=delta[i]


cipher_dec = AES.new(key,AES.MODE_CBC,iv)
print(cipher_dec.decrypt(ciphertext_array))
print(unpad(cipher_dec.decrypt(ciphertext_array),AES.block_size))
