import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES

from attacks.ECBCopyPaste.ECB_CopyPaste_server import profile_for,encode_profile

from mysecrets import HOST, PORT



# first test connection

server = remote (HOST, PORT)

input = b'aaaaaaa@b.com'

server.send(input)
encrypted_cookie = server.recv(1024)
print(encrypted_cookie.hex())

server.close()

print("-------")
print(profile_for(input.decode()))
print(encode_profile(profile_for(input.decode())))
prof = encode_profile(profile_for(input.decode()))
print(prof[0:16])
print(prof[16:32])
print(prof[32:48]) #<-- to substitute


# send aligned user (get blocks C1.1 and C1.2)
admin_str = b'admin'
admin_full_block = pad(admin_str,AES.block_size)
print(admin_full_block)
new_input=b'aaaaaaaaaa' + admin_full_block
print(encode_profile(profile_for(new_input.decode())))

server = remote (HOST, PORT)

server.send(new_input)
encrypted_cookie2 = server.recv(1024)
print(encrypted_cookie2.hex())

server.close()




#build the modified cookie

final_cookie = encrypted_cookie[0:32] + encrypted_cookie2[16:32]

from mysecrets import ecb_oracle_key
cipher = AES.new(ecb_oracle_key,AES.MODE_ECB)
p = cipher.decrypt(final_cookie)
print(p)
print(unpad(p,AES.block_size))



#
# from mysecrets import ecb_oracle_key
# cipher = AES.new(ecb_oracle_key,AES.MODE_ECB)
# p = cipher.decrypt(final_cookie)
# print(p)
#
# for i in range(3):
#     print(p[i*16:(i+1)*16])
#
# print(unpad(p,AES.block_size))


test_server = remote(HOST,PORT+100)
test_server.send(final_cookie)
msg = test_server.recv(1024)
print(msg)
