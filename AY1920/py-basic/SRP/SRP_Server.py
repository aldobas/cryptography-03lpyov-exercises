import socket
import sys
import srptools
import json
from base64 import b64decode, b64encode
from Crypto.Random import get_random_bytes

from srptools import SRPServerSession,SRPContext

from mysecrets import cbc_oracle_key as key, HOST, PORT

DATA_SIZE = 65535

USERNAME = 'aldo'
PASSWORD = 'safe_passwd'

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

    #this should be done offline, only once, the server should store somewhere these data

    context = SRPContext(USERNAME, PASSWORD)
    username, password_verifier, server_salt = context.get_user_data_triplet()
    print(username)
    print(password_verifier)
    print(server_salt)

    prime = context.prime
    gen = context.generator
    print(prime)
    print(gen)


    # generate user-based server parameters
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier)
    server_public = server_session.public
    print("server public= "  + str(server_public))
    server_data = json.dumps({'prime': prime, 'generator': gen, 'server_verifier': server_public, 'server_salt' : server_salt})
    conn.send(server_data.encode())


    # receive client parameters
    user_data = conn.recv(DATA_SIZE).decode()
    client_parameters = json.loads(user_data)
    # print(client_parameters)
    print("client public =    "  + str(client_parameters['client_parameter']))
    print("client key proof = "  + str(client_parameters['session_key_proof']))

    # generate server parameters
    server_session.process(client_parameters['client_parameter'], server_salt)

    # this is the agreed key
    print(server_session.key)


    conn.close()

s.close()
