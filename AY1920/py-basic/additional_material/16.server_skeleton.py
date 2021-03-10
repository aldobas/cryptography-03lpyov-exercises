import socket
import sys


HOST = ''   # Symbolic name, meaning all available interfaces
PORT = 12343


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
    print("I'm an echo server. Received input from " + addr[0] + ":"+ str(addr[1]))

    ##############33
    # do whatever you need
    input0 = conn.recv(1024)

    print(input0)

    conn.send(input0)



    #################3
    conn.close()

s.close()
