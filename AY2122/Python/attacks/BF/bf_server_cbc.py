from Crypto.Cipher import AES
import socket
import sys

from Crypto.Util.Padding import unpad, pad

from mysecrets import bf_key,bf_iv
from myconfig import HOST, PORT


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


# until this point is just uninteresting socket programming
# wait to accept a connection - blocking call
while 1:
    try:
        conn, addr = s.accept()
        print("Bit flipping server. Connection from " + addr[0] + ":"+ str(addr[1]))

        # receives the username from the client
        username = conn.recv(1024)
        cookie = b'username='+username+b',admin=0'
        print(cookie)

        # encrypt cookie info
        cipher = AES.new(bf_key,AES.MODE_CBC,bf_iv)
        ciphertext = cipher.encrypt(pad(cookie,AES.block_size))

        #send the encrypted cookie to the client
        conn.send(ciphertext)
        print("...cookie sent.")


        ######
        # after a while, when the user wants to connect again
        # sends its cookie, the one previously received
        ######

        received_cookie = conn.recv(1024)
        cipher_dec = AES.new(bf_key,AES.MODE_CBC,bf_iv)
        decrypted = unpad(cipher_dec.decrypt(received_cookie),AES.block_size)
        print(decrypted)

        # only the administrator will have the admin field set to 1
        # when they show back, we recognize them
        if b'admin=1' in decrypted:
            print("You are an admin!")
            conn.send("You are an admin!".encode())
        else:
            i1 = decrypted.index(b'=')
            i2 = decrypted.index(b',')
            msg = "welcome"+decrypted[i1:i2].decode('utf-8')
            print("You are a normal user")
            print(msg)
            conn.send(msg.encode())
        conn.close()
    except Exception:
        conn.send(b'Errors!')
        conn.close()

s.close()
