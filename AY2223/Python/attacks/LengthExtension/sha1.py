from hashlib import sha1


#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ----------------------------------------------------------------------
# Copyright (c) 2014 Pablo Caro. All Rights Reserved.
# Pablo Caro <me@pcaro.es> - https://pcaro.es/
# SHA1.py
# ----------------------------------------------------------------------

import sys

sniffed_dgst = "13cf30c5374f2dfb45e71d9e1606f8b8a3f7b342"

class SHA1:
    def __init__(self):
        # self.__H = [
        #     0x67452301,
        #     0xEFCDAB89,
        #     0x98BADCFE,
        #     0x10325476,
        #     0xC3D2E1F0
        #     ]

         self.__H = [None] * 5
         for i in range(5):
             self.__H[i] = int("0x" + sniffed_dgst[i * 8:(i + 1) * 8],16)
         print(self.__H)

    #def __init__(self,s):
    #    self.__H = [None] * 5
    #    for i in range(5):
    #        self.__H[i] = int("0x" + sniffed_dgst[i * 8:(i + 1) * 8], 16)
    #    print(self.__H)


    def __str__(self):
        return ''.join((hex(h)[2:]).rjust(8, '0') for h in self.__H)

    # Private static methods used for internal operations.
    @staticmethod
    def __ROTL(n, x, w=32):
        return ((x << n) | (x >> w - n))

    @staticmethod
    def __padding(stream):
        l = len(stream)  # Bytes
        l += 512//8

        hl = [int((hex(l * 8)[2:]).rjust(16, '0')[i:i + 2], 16)
              for i in range(0, 16, 2)]

        l0 = (56 - l) % 64
        if not l0:
            l0 = 64

        if isinstance(stream, str):
            stream += chr(0b10000000)
            stream += chr(0) * (l0 - 1)
            for a in hl:
                stream += chr(a)
        elif isinstance(stream, bytes):
            stream += bytes([0b10000000])
            stream += bytes(l0 - 1)
            stream += bytes(hl)

        return stream

    @staticmethod
    def __prepare(stream):
        M = []
        n_blocks = len(stream) // 64

        stream = bytearray(stream)

        for i in range(n_blocks):  # 64 Bytes per Block
            m = []

            for j in range(16):  # 16 Words per Block
                n = 0
                for k in range(4):  # 4 Bytes per Word
                    n <<= 8
                    n += stream[i*64 + j*4 + k]

                m.append(n)

            M.append(m[:])

        return M

    @staticmethod
    def __debug_print(t, a, b, c, d, e):
        print('t = {0} : \t'.format(t),
              (hex(a)[2:]).rjust(8, '0'),
              (hex(b)[2:]).rjust(8, '0'),
              (hex(c)[2:]).rjust(8, '0'),
              (hex(d)[2:]).rjust(8, '0'),
              (hex(e)[2:]).rjust(8, '0')
              )

    # Private instance methods used for internal operations.
    def __process_block(self, block):
        MASK = 2**32-1

        W = block[:]
        for t in range(16, 80):
            W.append(SHA1.__ROTL(1, (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]))
                     & MASK)

        a, b, c, d, e = self.__H[:]

        for t in range(80):
            if t <= 19:
                K = 0x5a827999
                f = (b & c) ^ (~b & d)
            elif t <= 39:
                K = 0x6ed9eba1
                f = b ^ c ^ d
            elif t <= 59:
                K = 0x8f1bbcdc
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                K = 0xca62c1d6
                f = b ^ c ^ d

            T = ((SHA1.__ROTL(5, a) + f + e + K + W[t]) & MASK)
            e = d
            d = c
            c = SHA1.__ROTL(30, b) & MASK
            b = a
            a = T

            #SHA1.debug_print(t, a,b,c,d,e)

        self.__H[0] = (a + self.__H[0]) & MASK
        self.__H[1] = (b + self.__H[1]) & MASK
        self.__H[2] = (c + self.__H[2]) & MASK
        self.__H[3] = (d + self.__H[3]) & MASK
        self.__H[4] = (e + self.__H[4]) & MASK

    # Public methods for class use.
    def update(self, stream):
        print(stream)
        stream = SHA1.__padding(stream)
        print(stream)
        stream = SHA1.__prepare(stream)

        print(stream)

        for block in stream:
            self.__process_block(block)

    def digest(self):
        pass

    def hexdigest(self):
        s = ''
        for h in self.__H:
            s += (hex(h)[2:]).rjust(8, '0')
        return s


def usage():
    print('Usage: python SHA1.py <file> [<file> ...]')
    sys.exit()

def padding(stream):
    l = len(stream)  # Bytes
    hl = [int((hex(l*8)[2:]).rjust(16, '0')[i:i+2], 16)
          for i in range(0, 16, 2)]

    l0 = (56 - l) % 64
    if not l0:
        l0 = 64

    if isinstance(stream, str):
        stream += chr(0b10000000)
        stream += chr(0)*(l0-1)
        for a in hl:
            stream += chr(a)
    elif isinstance(stream, bytes):
        stream += bytes([0b10000000])
        stream += bytes(l0-1)
        stream += bytes(hl)

    return stream


def main():

    secret = b'this is a secret!!'
    # keyed-digest  k || message --> MAC = m
    # starting from m --> we build keyed-digest(message||additional_data) without knowing k

    message = b'This is the message'  # public data (we are considering integrity, not confidentiality)
    to_add = b' ...and this is the message to append'

    print(len(secret+message))

    padded_msg = padding(secret+message)

    print(padded_msg)

    #

    h = sha1()
    h.update(secret+message)
    digest = h.digest()
    hexdgst = h.hexdigest()
    print(digest)
    print(hexdgst)



    for i in range(len(hexdgst)//8):
        print(hexdgst[i*8:(i+1)*8])


########################3
    h2 = sha1()
    h2.update(padding(secret+message)+to_add)
    print(h2.hexdigest())

    h3 = sha1()
    h3.update(padded_msg+to_add)
    print("full: "+str(h3.hexdigest()))


    # digest = hasher.digest()

    # print(padding(secret + message))


########################
    hasher = SHA1(h.hexdigest())
    hasher.update(to_add)
    print(hasher.hexdigest())


    # hasher = SHA1()
    # hasher.update(to_add)
    # print(hasher.hexdigest())



if __name__ == '__main__':
    main()
