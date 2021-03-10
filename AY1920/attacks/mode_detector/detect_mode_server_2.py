import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

from mysecrets import ecb_oracle_key,HOST,PORT

# HOST = ''   # Symbolic name, meaning all available interfaces
# PORT = 12341

ECB_MODE = 0
CBC_MODE = 1

MAX_INDEX = 5


def prepare_plaintext(plaintext):
    x = bytearray()

    for i in range(0,len(plaintext)//15):
        x += plaintext[i*15:(i+1)*15]
        x += (i%MAX_INDEX).to_bytes(1, byteorder='big')

    x+=plaintext[(i+1)*15:]

    return x


if __name__ == '__main__':

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


        selected_mode = getrandbits(1)
        print("Seledcted mode = " + str(selected_mode))

        from_client = conn.recv(1024)
        message = b'This is what I received: ' + from_client + b' -- END OF MESSAGE'
        print("Plaintext: " + message.decode())

        if(selected_mode == ECB_MODE):
            cipher = AES.new( ecb_oracle_key, AES.MODE_ECB )
        else:
            cipher = AES.new( ecb_oracle_key, AES.MODE_CBC )


        plaintext = prepare_plaintext(message)

        print(pad(plaintext,AES.block_size))

        ciphertext = cipher.encrypt(pad(plaintext,AES.block_size))

        conn.send(ciphertext)
        conn.close()

    s.close()
