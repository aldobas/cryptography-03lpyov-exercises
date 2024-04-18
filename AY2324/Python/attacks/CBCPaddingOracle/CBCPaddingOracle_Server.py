import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from attacks.CBCPaddingOracle.mysecrets import cbc_oracle_key as key
from attacks.CBCPaddingOracle.myconfig import HOST, PORT


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
    print('A new padding test requested by ' + addr[0] + ':' + str(addr[1]))

    # get the IV from the client
    iv = conn.recv(AES.block_size)
    # get the ciphertect from the client
    ciphertext = conn.recv(1024)

    #decrypts the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv )

    try:
        unpad(cipher.decrypt(ciphertext),AES.block_size)
        #PKCS#5  01 / 0202 / 030303 / ...


    except ValueError:
        conn.send(b'NO')
        continue


    conn.send(b'OK')

    conn.close()

s.close()
