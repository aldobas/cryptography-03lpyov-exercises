from base64 import b64decode
import numpy
from string import *

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
} # ','

# from CryptoPals S3C19/S3C20
# same key and same nonce: mount a keystream reuse attack
# encoded_ciphertexts = [b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==", b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==", b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk", b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=", b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=", b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", b"VG8gcGxlYXNlIGEgY29tcGFuaW9u", b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=", b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=", b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==", b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==", b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==", b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", b"U2hlIHJvZGUgdG8gaGFycmllcnM/", b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=", b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=", b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==", b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==", b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=", b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=", b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", b"SW4gdGhlIGNhc3VhbCBjb21lZHk7", b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=", b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]
encoded_ciphertexts = [b'wMf5jRaW+h+ZIzmbCVPA2jRaiIqXtWbjpzsPXUWYgjvN3WGC8H84Wg==', b'wMf13kWD/AKeZjTIRU/ZxDgKk5WXsW728jcaVxCEnm7IlHeYsWI+EdkXLjMJmUcZ5IMPeB6K2iY=', b'wMf1jFPU9AKXIzaNXgDBwDgUm5aXu2rmpjsbBAyPzSLWm2bQ5X43GtkGYTBFgksfr8wKOQCHxiY=', b'wMf13kCd8AfSZSKHRADBwDRakIzQsXv6vSsaQUWElS3WiWaUsXMgEZdHNStMy0UV/NdMahWP0Ge9w/pygqSQZgMr0UeA', b'x8f13kGV5lCBYjTIXU+VwDQbjsXDsW7m8jgAVgCHgSfajiOR43N2EpgEKC1Oy00C+8oCegSHzGbzwus31qKeMAc1wFzIe3QYc1XEo/wStUfS+6cxTs4kINf3BpEKezO63jO/3EDypB0IrW5c0lY3', b'wMf13kKb4ALSYSWbCVfU23EKnYbcvGuypTcdTEWViCvRnGSVsXE/BpUUYStMikwT4cRMbR+Zwnq3huo6k7+DMAgizEGOc3MHd1eQuucQ8w==', b'2dawmlOa4RmBd3CcTEzZ23EXmcXDsW7m8j0BQRKIgymfn3GZ8n0lVJAUYTVMmVFa7cIIORaB0Siqyesg1qKUdRIvmg==', b'wMf13kWB+1CaYjTIWkXBiDAUmMXEti/6szpJTAySzSrNmGKd4jg=', b'x8f13lqd4xWWIz+GCW3axjofhcX9rGH1vjtJdgqAiW7ek2fQ5X43ANkUJCZEjkxa+8xMfAiez2m6yL4zmrrRfwBn3FDcMmQFYFiKqPAbuECN9Q==', b'wMf1jFPT5lCTIyKNSFPaxnEOlITD+X39oTsaBA2AmyufiWuf43glWg==', b'28mwnVmB5wOXL3CbQUWVxD4MmZaXsWrg8i4ASg7BjzvRk3rQ4no/BIkCMzAH', b'wMf13lSY/B6Zaj6PCUzczzkOj8XYvy/mujtJRQuViCDRnCOE/mEzBtkEIC5My0EU+8xMfx+N1nvzzOshgvaQY0YOlF3Lc2UVMljEo/oAuRONta4gAg==', b'wNj5kBbAuB2dbSSABE/ZzCJaj4nSqXuyuzBJUA2EzT3XnGeVsXkwVI0PJGNZikQXr9cefBXO1GC6yvtygr6UMAsowF3LYDcFc1eKqvFVtF3er6c1DNQlL40=', b'wMf13lWY+gWWcHCORlLYzTVanoDWrHv7tCsFBASPhCPekXDQ+Hh2AJECYTBCkggO58IYORWYxman0/8+mq/RcxQi1UHLdjcQMk2LvfsUuVzer6BwW9U1IMj3Ap8PZ3y0', b'0sPlmFCNtQCbbTvIXE7cyz4IkpaXuH338j9JVAqRmCLejyOD5XciAYpHMjpEiUcWr8IBdh6Jg2WyxfY91ruUfkg=', b'1dywllPU4hGbdzWMCUba2nEOlICXqmf9pTsbBBGOzTnej27csX4zVJcINSpKjkxa+8sNbVCGxiiwyes+kvaZdQc1lELPZnIDMlqMrvsSuBOKvqIgSdUxNdalD9A=', b'wMf13mKH4B6TbjnIXkHDzXEZjoTEsWr28j8ORQyPnjqfiWuVsWQ3HYoCJWNBhF0J6tBMeB6Kg2qhyfU31qKZdUY33VnHfHACMliX7/wT/UeWvrZwW8IiJIOjBZENYG/z3Dao0g==', b'w8bklhaVtQObbTeETADTxDgK3IrR+Xv6t34KSwyPwW7XlHDQ/X8wEdkEKSJHjE0er8UDaxWYxnr9', b'2sDn3n/U+xWXZ3CcRgDFxz8emZeXtHaytyYAVxGEgy3a3WKe9TY3B5JHLDpajkQcr8oKOTnJziin1Os+j/aDdQcrmg==', b'3MqwiVeHtRSbcDGYWU/cxiUfmMXAsWr88jYMBAOOmCDb3XeY9DY0EZgEKWNdhAgY6oMfdlCdwma3374zmLLRZA4ilEbbfDcCfRmXuvsbpB0=', b'wMf13lCd5hjSZyKNSE3QzHEVmsXSqmzzojcHQ0WVhSufm2qD+XQ5A5VHIC1Ny0EU+8xMbRiLg3y8z/I3gvaGeAM10RXGdzcCc07Ep/wG/VWMsqo+SIc3Lo0=', b'w8qwlleC8FCLbCWGTgDewTUJ3JLfti/9tCoMSkWWjCLU3Wqe5Xl2G4wVYTFGhEVa7tdMdxmJy3zzwPEg1qCQYg8owUaOYHIQYVaKvLUcs1CSrqs5QsBwIs+4HZAKKHb0nymzmRD0uwYSq3MW', b'wMf13kKb7FCQcT+dTkjBiDMbn46Xv2D8tn4EQQiOnyfajiOf9zY0EZAJJmNFhFsOr8oCOQSGxiihx/c81rCeYgM0wBs=', b'wMf13lSR5gTSaDWRCUzcxTRajIzS+Wbh8i0dTQmNzTvP3WWf4zYyEZsGNSYH', b'wMf13kWA5xGcZDWaCU/TzjgZlYTDvHyypjYMBAiEjCKR', b'3Y/nkUOY8VCQZnCMTEzczzkOmYGXsGmypjYMBBaEjG7ImHGVsXAjGJVHLiUJiF0Z+s4OfALOyX26xft8', b'3Mbj3lud+xTSdDGbCULZxyYU3JHfuHuypjYMVgDBmi/M3W2f5X4/Gp5HKC0JmFgb7MZMfAiNxninhu0il7WUMA8zx1DCdDk=', b'zcDljBaT/AKeZSKBTE7RiDMViYLfrS/rvSsbBAOAmyHNlHeVsXU5G5IOJGNKmUEJ/4MPfAKLwmTzxOsm1rCeYgEowBXafTcWd03EovwZth0=', b'1tril1OQtRSXZiDIQE6V3Dkf3JbZtni+8jYMBA2OnSvb3WuZ4jY0FY0TJDFAjlta+MYefFCI0W2gzr47mPaZeRVn1UPPfnYfcVGB7/cQvFCRteE=', b'wMf13lmY8VCTcyCETADHzScfkJaXsGGyuyoaBASUmSbQj2qE6Dg=', b'3Mri3kWX5xWTbnCbQEzQxjIfmMXDsWqyoDEeQBzBmSvak2KX9GQlWg==', b'0M7+3leA8FCGazXISkza3TUJ3InesmqysTEdUAqPzS3ek2eJvw==', b'0MD+2ULU5RmBcHCBRwDY0XEdnZfTvGGyszANBBGEgSKfkGbQ6HkjU4sCYTdbkkEU6IMYdlCGxmSjhvMr1qadcQgzxxXJYHgGPA==', b'w8f1kBa9tROdbDvIWlDUzzkfiJHe9S/b8jIATwDBmSGfn2yZ/TY/ANkGYSVMnAgX5s0ZbRWdg3iy1epyl7rRdAMpwFCOYXhRZlGB7/sasleSvrxwTdU1YdCiGpsLKGz21i2rmULu+Q==', b'18D9nF+a8APSYiKNCU7aiD0VkoLSqy/4py0dBAOOn27ZnHGd4jg=', b'wMf13lWG+geWIymNRUzGiDAUmMXEun33szMaBAOOn27SknGVsXszGZwUbw==', b'wMf13kOG8hWcd3CLSFLQiDIfkpHSqy/lsy1JQgmOgiramSOH+GI+VIkGNSpMhVwJr8IKbRWcg3y7w748k6GCMAkhlFSOfHIGMl2BrvEZpBOIsr0lX4cnIND3B58dbT/qyj+3lVO5', b'xM75jBaN+gWAIzSNWknSxjQI3IbYrm39q34BRRHBmifLlSOD8mM0FdkAJCJby04V/YMNOR2Lzmehx/w+k/aecwUmx1zBfDk=', b'2sDykVKNtRiTcHCNR0Pa3T8OmZfSvS/zvH4MXBWNgj3Wi2bQ9Xc/B4BHIC1Ny0QT+cYIOQSBg3y2yvJygr6UMBIm2FCA', b'wMf13kKG4ASaIzmbCVTdySVahYrC+X/zq34PSxfBlCHKjyOc+HAzB40eLSYJgkZa58wZawPA', b'3MqwiVma8RWAZjTIQEaV2zkf3JLYrGP28j8ZVBeEjifeiWbQ+X8lVI0IJC1IgkRa7MwAdRWN12G8yLA=', b'3duwilmb/lCaaj3ISADYxz8OlMXDti/0uzAAVw3BmSba3W6V8Hp4', b'3MqwmF+T4AKXZ3CJCUbQ33EJiIzUsnyyvThJQByPjCPWiWbQ5nMkEdkCIDBAjlpa+8sNd1CPg2661fY7mLHRYAkr0RXafTcSc02Hp7UTtECW9Q==', b'3du3jRaZ4BOaIz2HW0WVzDgcmozUrGPm8ioGBBWNjDefiWae/38lVI4ONSsJiggY4NQAcB6Jg2qyyvJygr6QfkYuwBXHYTcFfRmGoOIZ/USXr6dwTYckJM25A41Zan7203M=', b'wMf13kWc+h+GZiLIWkHM23Edk4rTu3b38ioGBA2Inm7TknWVvw==', b'3Mqwml+Q+1eGIyWGTUXH2yUbkoGXrmfr8ioBQUWDhDzb3XSR/2IzENkTLmNbgkwfr9cEfFCMymuqxfI32A==', b'3MqwmkSR9B2XZ3CHTwDQySUTkoKXvn33tzBJRRWRgSvM3XSZ5X52A5YVLDAH', b'3duwiVeHtRiXcXCOQFLG3HEfhJXSq2b3vD0MBBGTjCfRlG2XsXd2BpgOLyFGnAgP4coPdgKAjQ==', b'18DljFeT8FCTbTTIWlTA2DgelZHO+Xj3oDtJRQmNzSba3WuR9Tg=', b'wMf13lmE5R+AdyWGQFTMiD4c3ISXtWb0tyoASQDBnS/MjmaUsXQzEpYVJGNBgkVa7tBMcRXO13q6w/pygrnRdAMk3VHLMnUUZk6BqvtVvBOdtKE1DMgiYcL3CYsJJg==']
ciphertexts = [b64decode(encoded_ciphertexts[i]) for i in range(len(encoded_ciphertexts))]

print("stats")
print(len(ciphertexts))

longest_c = max(ciphertexts, key=len)
max_len = len(longest_c)
print(len(longest_c))

shortest_c = min(ciphertexts, key=len)
min_len = len(shortest_c)
print(len(shortest_c))


#################################################
# guess the first byte: naive approach: count the ascii chars

counters = numpy.zeros(256,dtype=int)

for guessed_byte in range(256):
    for c in ciphertexts:
        if chr(c[0] ^ guessed_byte) in ascii_letters:
            counters[guessed_byte] +=1

max_matches = max(counters)
print(max_matches)

match_list = [(counters[i],i) for i in range(256)]
# print(match_list)
ordered_match_list = sorted(match_list, reverse=True)
# print(ordered_match_list)

candidates = []
for pair in ordered_match_list:
    if pair[0] < max_matches * .95:
        break
    candidates.append(pair)

print(candidates)
#
#
# #################################################
# # guess the second byte: naive approach: count the ascii chars
#
# counters = numpy.zeros(256,dtype=int)
#
# for guessed_byte in range(256):
#     for c in ciphertexts:
#         if chr(c[1] ^ guessed_byte) in ascii_letters:
#             counters[guessed_byte] +=1
#
# max_matches = max(counters)
# print(max_matches)
#
# match_list = [(counters[i],i) for i in range(256)]
# # print(match_list)
# ordered_match_list = sorted(match_list, reverse=True)
# # print(ordered_match_list)
#
# candidates = []
# for pair in ordered_match_list:
#     if pair[0] < max_matches * .95:
#         break
#     candidates.append(pair)
#
# print(candidates)
#
#
#
# ##############################33
# # guess all the bytes
#
# candidates_list = []
#
# for byte_to_guess in range(min_len):
#     counters = numpy.zeros(256, dtype=int)
#
#     for guessed_byte in range(256):
#         for c in ciphertexts:
#             if chr(c[byte_to_guess] ^ guessed_byte) in printable:
#                 counters[guessed_byte] += 1
#
#     max_matches = max(counters)
#     # print(max_matches)
#
#     match_list = [(counters[i], i) for i in range(256)]
#     # print(match_list)
#     ordered_match_list = sorted(match_list, reverse=True)
#     # print(ordered_match_list)
#
#     candidates = []
#     for pair in ordered_match_list:
#         if pair[0] < max_matches * .95:
#             break
#         candidates.append(pair)
#
#     # print(candidates)
#     candidates_list.append(candidates)
#
# # for c in candidates_list:
# #     print(c)
#
#
# keystream = b''
# for x in candidates_list:
#     keystream += x[0][1].to_bytes(1,byteorder='big')
#
# from Crypto.Util.strxor import strxor
#
# for c in ciphertexts:
#     print(strxor(c[:min_len],keystream))



##################################################
# approach with stats

candidates_list = []

for byte_to_guess in range(max_len):
    freqs = numpy.zeros(256, dtype=float)

    for guessed_byte in range(256):
        for c in ciphertexts:
            if byte_to_guess >= len(c):
                continue
            if chr(c[byte_to_guess] ^ guessed_byte) in printable:
                freqs[guessed_byte] += CHARACTER_FREQ.get(chr(c[byte_to_guess] ^ guessed_byte).lower(),0)

    max_matches = max(freqs)
    # print(max_matches)

    match_list = [(freqs[i], i) for i in range(256)]
    # print(match_list)
    ordered_match_list = sorted(match_list, reverse=True)
    # print(ordered_match_list)

    # candidates = []
    # for pair in ordered_match_list:
    #     if pair[0] < max_matches * .95:
    #         break
    #     candidates.append(pair)

    # print(candidates)
    candidates_list.append(ordered_match_list)

# for c in candidates_list:
#     print(c)


keystream = bytearray()
for x in candidates_list:
    keystream += x[0][1].to_bytes(1,byteorder='big')

from Crypto.Util.strxor import strxor

keystream[0] = 148

dec = keystream[1] ^ ciphertexts[0][1]
dec2 = keystream[2] ^ ciphertexts[0][2]

mask = dec ^ ord('h')
keystream[1] = keystream[1] ^ mask
mask2 = dec2 ^ ord('i')
keystream[2] = keystream[2] ^ mask2



for c in ciphertexts:
    l = min(len(keystream),len(c))
    print(strxor(c[:l],keystream[:l]))

