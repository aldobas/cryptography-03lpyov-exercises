
#encoding: utf-8
import random
import struct, hashlib
import time, re

#4字节
def Endian(b):
  print(b[0:4])
  return [struct.unpack('<I', bytearray(b[i:i+4]))[0] for i in range(0, len(b), 4)]

#循环左/右移
def LeftRot(n, b): return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff
def RightRot(n, b): return ((n >> b) | ((n & 0xffffffff) << (32 - b))) & 0xffffffff

#MD4中的函数
def F(x, y, z): return x & y | ~x & z
def G(x, y, z): return x & y | x & z | y & z
def H(x, y, z): return x ^ y ^ z

def FF(a, b, c, d, k, s, X): return LeftRot(a + F(b, c, d) + X[k], s)
def GG(a, b, c, d, k, s, X): return LeftRot(a + G(b, c, d) + X[k] + 0x5a827999, s)
def HH(a, b, c, d, k, s, X): return LeftRot(a + H(b, c, d) + X[k] + 0x6ed9eba1, s)

#计算MD4
def MD4(m): 
  md4 = hashlib.new('md4')
  md4.update(m)
  return md4.hexdigest()

#第一轮修改
def FirstRound(abcd, j, i, s, x, constraints):
  v = LeftRot(abcd[j%4] + F(abcd[(j+1)%4], abcd[(j+2)%4], abcd[(j+3)%4]) + x[i], s)
  for constraint in constraints:
    if   constraint[0] == '=': v ^= (v ^ abcd[(j+1)%4]) & (2 ** constraint[1]) #等于下一个链变量
    elif constraint[0] == '0': v &= ~(2 ** constraint[1]) # =0的位
    elif constraint[0] == '1': v |= 2 ** constraint[1] # =1的位
    
  #反推，更新m
  x[i] = (RightRot(v, s) - abcd[j%4] - F(abcd[(j+1)%4], abcd[(j+2)%4], abcd[(j+3)%4])) % 2**32
  abcd[j%4] = v #更新链变量

def FindCollision(m):
  x = Endian(m) # 小端序
  initial_abcd = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  abcd = initial_abcd[:]
  
  #第一轮的所有条件
  constraints = [
    [['=', 6]],[['0', 6],['=', 7],['=', 10]],
    [['1', 6],['1', 7],['0', 10],['=', 25]],
    [['1', 6],['0', 7],['0', 10],['0', 25]],
    [['1', 7],['1', 10],['0', 25],['=', 13]],
    [['0', 13],['=', 18],['=', 19],['=', 20],['=', 21],['1', 25]],
    [['=', 12],['0', 13],['=', 14],['0', 18],['0', 19],['1', 20],['0', 21]],
    [['1', 12],['1', 13],['0', 14],['=', 16],['0', 18],['0', 19],['0', 20],['0', 21]],
    [['1', 12],['1', 13],['1', 14],['0', 16],['0', 18],['0', 19],['0', 20],['=', 22],['1', 21],['=', 25]],
    [['1', 12],['1', 13],['1', 14],['0', 16],['0', 19],['1', 20],['1', 21],['0', 22],['1', 25],['=', 29]],
    [['1', 16],['0', 19],['0', 20],['0', 21],['0', 22],['0', 25],['1', 29],['=', 31]],
    [['0', 19],['1', 20],['1', 21],['=', 22],['1', 25],['0', 29],['0', 31]],
    [['0', 22],['0', 25],['=', 26],['=', 28],['1', 29],['0', 31]],
    [['0', 22],['0', 25],['1', 26],['1', 28],['0', 29],['1', 31]],
    [['=', 18],['1', 22],['1', 25],['0', 26],['0', 28],['0', 29]],
    [['0', 18],['=', 25], ['1', 26],['1', 28],['0', 29],['=', 31]]
  ]

  shift = [3, 7, 11, 19] * 4
  change = [0, 3, 2, 1] * 4

  #使满足第一轮的所有条件
  for i in range(16):
    FirstRound(abcd, change[i], i, shift[i], x, constraints[i])
  
  #第二轮的所有条件
  constraints2 = [
    [['=', 18, 2], ['1', 25], ['0', 26], ['1', 28], ['1', 31]],
    [['=', 18, 0], ['=', 25, 1], ['=', 26, 1], ['=', 28, 1], ['=', 31, 1]]
  ]

  #计算a5
  a5 = GG(abcd[0], abcd[1], abcd[2], abcd[3], 0, 3, x)
  for constraint in constraints2[0]:
    if   constraint[0] == '=': a5 ^= ((a5 ^ abcd[constraint[2]]) & (2 ** constraint[1]))
    elif constraint[0] == '0': a5 &= ~(2 ** constraint[1])
    elif constraint[0] == '1': a5 |= (2 ** constraint[1])

  q = (RightRot(a5, 3) - abcd[0] - G(abcd[1], abcd[2], abcd[3]) - 0x5a827999) % 2**32
  
  #多步修正
  a0, b0, c0, d0 = initial_abcd[0], initial_abcd[1], initial_abcd[2], initial_abcd[3]
  a_ = FF(a0,b0,c0,d0, 0, 3, [q]) #计算a'
  a1 = FF(a0,b0,c0,d0, 0, 3, x) #按照原来的方法算
  d1 = FF(d0,a1,b0,c0, 1, 7, x) 
  x[0] = q #更新m0
  q = x[1]
  x[1] = (RightRot(d1,  7) - d0 - F(a_, b0, c0)) % 2**32
  
  c1 = FF(c0,d1,a1,b0, 2, 11, x)
  x[2] = (RightRot(c1, 11) - c0 - F(d1, a_, b0)) % 2**32
  
  b1 = FF(b0,c1,d1,a1, 3, 19, x)
  x[3] = (RightRot(b1, 19) - b0 - F(c1, d1, a_)) % 2**32
  
  a2 = FF(a1,b1,c1,d1, 4, 3, x)
  x[4] = (RightRot(a2,  3) - a_ - F(b1, c1, d1)) % 2**32

  abcd[0] = a5
  
  #计算d5
  d5 = GG(abcd[3], abcd[0], abcd[1], abcd[2], 4, 5, x)

  for constraint in constraints2[1]:
    if   constraint[0] == '=': d5 ^= ((d5 ^ abcd[constraint[2]]) & (2 ** constraint[1]))
    elif constraint[0] == '0': d5 &= ~(2 ** constraint[1])
    elif constraint[0] == '1': d5 |= (2 ** constraint[1])

  q = (RightRot(d5, 5) - abcd[3] - G(abcd[0], abcd[1], abcd[2]) - 0x5a827999) % 2**32
  
  #多步修正
  a, b, c, d = initial_abcd[0], initial_abcd[1], initial_abcd[2], initial_abcd[3]
  a = FF(a,b,c,d, 0, 3, x)
  d = FF(d,a,b,c, 1, 7, x)
  c = FF(c,d,a,b, 2,11, x)
  b = FF(b,c,d,a, 3,19, x)

  a2_ = FF(a,b,c,d, 4, 3, [q] * 5)
  a2 = FF(a,b,c,d, 4, 3, x)
  d2 = FF(d,a2,b,c, 5, 7, x)
  
  x[4] = q
  q = x[5]
  x[5] = (RightRot(d2,  7) - d - F(a2_, b, c)) % 2 ** 32
  
  c2 = FF(c,d2,a2,b, 6, 11, x)
  x[6] = (RightRot(c2, 11) - c - F(d2, a2_, b)) % 2 ** 32
  
  b2 = FF(b,c2,d2,a2, 7, 19, x)
  x[7] = (RightRot(b2, 19) - b - F(c2, d2, a2_)) % 2 ** 32
  
  a3 = FF(a2,b2,c2,d2, 8, 3, x)
  x[8] = (RightRot(a3,  3) - a2_ - F(b2, c2, d2)) % 2 ** 32

  m = ''.join([struct.pack('<I', i) for i in x])
  m_ = CreateCollision(m) #碰撞微分

  if MD4(m) == MD4(m_):
    return m, m_
  
  return None, None

#对于修正后的M，有一定概率可以通过碰撞微分找到M'
def CreateCollision(m):
  x = list(Endian(m))
  x[1] = (x[1] + (2 ** 31)) % 2**32
  x[2] = (x[2] + ((2 ** 31) - (2 ** 28))) % 2**32
  x[12] = (x[12] - (2 ** 16)) % 2**32
  return ''.join([struct.pack('<I', i) for i in x])

def Collision():
  num = 1
  while 1:
    #随机的M
    m = [chr(i) for i in [random.randint(0, 2 ** 8 - 1) for i in range(64)]]
    ma, mb = FindCollision(m)
    if ma:
      #winsound.Beep(600, 1000)
      break
    num += 1
  
  h1 = MD4(ma)
  h2 = MD4(mb)
  return ma.encode('hex'), mb.encode('hex'), h1, h2

# main()
time.time()
print('[+]Finding Collision...')
m1, m2, h1, h2 = Collision()
M1 = re.findall('.{4}', m1)
M2 = re.findall('.{4}', m2)

mm1 = ''
mm2 = ''
for i in range(len(M1)):
  if M1[i] != M2[i]:
    mm1 += '[' + M1[i] + ']'
    mm2 += '[' + M2[i] + ']'
  else:
    mm1 += M1[i]
    mm2 += M1[i]
    
print("  [-]The M1 is:", m1)
print( "  [-]The M2 is:", m2)
print ("  [-]M1 and M2 diff:\n    [*]" + mm1 + "\n    [*]" + mm2)
print ("  [-]The MD4(M1) is:", h1)
print ("  [-]The MD4(M2) is:", h2)
print ("[!]M1 == M2 ?", m1 == m2)
print ("[!]MD4(M1) == MD4(M2) ?", h1 == h2)
print ("[!]All done!")
print ("[!]Timer:", round(time.clock(), 2), "s")

# The diff in:
# m1[1] m2[1]
# m1[2] m2[2] 
# m1[12] m2[12]
