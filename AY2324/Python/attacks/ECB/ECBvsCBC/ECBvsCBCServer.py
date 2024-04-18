import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

from attacks.ECB.mysecrets import ecb_oracle_key
from attacks.ECB.myconfig import HOST,PORT


ECB_MODE = 0
CBC_MODE = 1

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

try:
    s.bind((HOST, PORT))
except socket.error as msg:
    print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
print('Socket bind complete')

s.listen(10)
print('Socket now listening')

#wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    #select a mode of operation: ECB = 0, CBC = 1
    selected_mode = getrandbits(1)
    print("Seledcted mode = ",end='')
    if(selected_mode == ECB_MODE):
        print("ECB")
    else:
        print("CBC")

    # receive the chosen plaintext from the user
    input0 = conn.recv(1024).decode()
    message = "This is what I received: " + input0 + " -- END OF MESSAGE"
    print("Plaintext: " +message)

    # encrypt plaintext with chosen mode
    if(selected_mode == ECB_MODE):
        cipher = AES.new( ecb_oracle_key, AES.MODE_ECB )
    else:
        cipher = AES.new( ecb_oracle_key, AES.MODE_CBC )

    # send ciphertext
    message = pad(message.encode(),AES.block_size)
    ciphertext = cipher.encrypt(message)
    conn.send(ciphertext)

    conn.close()

s.close()
