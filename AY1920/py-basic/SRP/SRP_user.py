import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *
from srptools import SRPContext, SRPClientSession
import json

from mysecrets import HOST,PORT, cbc_oracle_iv as iv

DATA_SIZE = 65535

USERNAME = 'aldo'
PASSWORD = 'safe_passwd'

if __name__ == '__main__':


    server = remote(HOST, PORT)

    #receive server verifier and salt, and all the public parameters
    received_data = server.recv(DATA_SIZE).decode()
    server_data = json.loads(received_data)
    print(server_data)
    # print("server public= "+str(server_data['server_verifier']))
    # print("server salt  = "+str(server_data['salt']))

    #compute client parameters
    client_session = SRPClientSession( SRPContext(USERNAME, PASSWORD, prime=server_data['prime'], generator=server_data['generator']))
    client_session.process(server_data['server_verifier'], server_data['server_salt'] )

    # Generate client public and session key proof.
    client_public = client_session.public
    print("client public = "+str(client_public))
    client_session_key_proof = client_session.key_proof.hex()
    print("session key proof = " + str(client_session_key_proof))
    print("session key proofB= " + str(client_session.key_proof))
    client_parameters = json.dumps({'client_parameter': client_public, 'session_key_proof': client_session_key_proof})
    server.send(client_parameters.encode())

    print(client_session.key)



    server.close()
