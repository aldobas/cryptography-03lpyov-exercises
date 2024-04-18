import sys
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from attacks.ECB.mysecrets import ecb_oracle_key as key
from attacks.ECB.myconfig import HOST,PORT,DELTA_PORT


###############################
def profile_for(email):

    email=email.replace('=','')
    email=email.replace('&','')

    dict = {}
    dict["email"] = email
    dict["UID"] = 10
    dict["role"] = "user"
    return dict


###############################
def encode_profile(dict):
    """
    :type dict: dictionary
    """
    s = ""
    i=0
    n = len(dict.keys())
    print(n)
    for key in dict.keys():
        s+=key+"="+str(dict[key])
        if i < (n-1):
            s+="&"
            i+=1
    return s

###############################

def encrypt_profile(encoded_profile):
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(),AES.block_size)
    print(plaintext)
    return cipher.encrypt(plaintext)

###############################
def decrypt_msg(ciphertext):
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext),AES.block_size)


if __name__ == '__main__':

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        s.bind((HOST, PORT+DELTA_PORT))
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

        received_cookie = conn.recv(1024)
        cipher_dec = AES.new(key,AES.MODE_ECB)

        try:
            decrypted = unpad(cipher_dec.decrypt(received_cookie),AES.block_size)
        except ValueError:
            print("Wrong padding")
            continue

        print(decrypted)

        # only the administrator will have the admin field set to 1
        # when they show back, we recognize them
        if b'role=admin' in decrypted:
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

s.close()



