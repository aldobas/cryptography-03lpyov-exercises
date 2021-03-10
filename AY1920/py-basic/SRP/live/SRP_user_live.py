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

    received_data = server.recv(DATA_SIZE).decode()
    server_data = json.loads(received_data)
    print(server_data['prime'])
    print(server_data['generator'])
    print(server_data['B'])
    print(server_data['server_salt'])

    #receive server verifier and salt, and all the public parameters
    client_session = SRPClientSession( SRPContext(USERNAME, PASSWORD, prime=server_data['prime'], generator = server_data['generator'] ) )
    client_session.process(server_data['B'], server_data['server_salt'])

    client_public_A = client_session.public
    print(client_public_A)
    client_session_key_proof = client_session.key_proof.hex()
    print(client_session_key_proof)

    client_parameters = json.dumps({'A':client_public_A,'client_session_key_proof':client_session_key_proof})
    print(client_parameters)

    server.send(client_parameters.encode())

    print("KEY = " + str(client_session.key))

    # receive the server key proof
    # client_session.verify_proof()


    #compute client parameters


    # Generate client public and session key proof.



    server.close()
