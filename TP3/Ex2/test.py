import hashlib, os
from functools import reduce
#from shakestream import ShakeStream


N = 256
Q = 3329 
DU = 10
DV = 4








def bits_to_bytes(b):
    B = bytearray([0] * (len(b) // 8))
    
    for i in range(len(b)):
        B[i // 8] += b[i] * 2 ** (i % 8)
    
    return bytes(B)


def bytes_to_bits(B):
    B_list = list(B)
    b = [0] * (len(B_list) * 8)
    
    for i in range(len(B_list)):
        for j in range(8):
            b[8 * i + j] = B_list[i] % 2
            B_list[i] //= 2

    return b


def byte_encode(d, F):
    b = [0] * (256 * d)
    for i in range(256):
        a = F[i]
        for j in range(d):
            b[i * d + j] = a % 2
            a = (a - b[i * d + j]) // 2
    
    return bits_to_bytes(b)


def byte_decode(d, B):
    m = 2 ** d if d < 12 else Q
    b = bytes_to_bits(B)
    F = [0] * 256
    for i in range(256):
        F[i] = sum(b[i * d + j] * (2 ** j) % m for j in range(d))
    
    return F


def sample_ntt(B):
    i, j = 0, 0
    ac = [0] * 256

    while j < 256:
        d1 = B[i] + 256 * (B[i + 1] % 16)
        d2 = (B[i + 1] // 16) + 16 * B[i + 2]

        if d1 < Q:
            ac[j] = d1
            j += 1

        if d2 < Q and j < 256:
            ac[j] = d2
            j += 1
            
        i += 3

    return ac


def sample_poly_cbd(B, eta):
    b = bytes_to_bits(B)
    f = [0] * 256
    
    for i in range(256):
        x = sum(b[2 * i * eta + j] for j in range(eta))
        y = sum(b[2 * i * eta + eta + j] for j in range(eta))
        f[i] = (x - y) % Q

    return f


def ntt(f):
    fc = f
    k = 1
    len = 128

    while len >= 2:
        start = 0
        while start < 256:
            zeta = ZETA[k]
            k += 1
            for j in range(start, start + len):
                t = (zeta * fc[j + len]) % Q
                fc[j + len] = (fc[j] - t) % Q
                fc[j] = (fc[j] + t) % Q

            start += 2 * len
            
        len //= 2

    return fc


def ntt_inv(fc):
    f = fc
    k = 127
    len = 2
    while len <= 128:
        start = 0
        while start < 256:
            zeta = ZETA[k]
            k -= 1
            for j in range(start, start + len):
                t = f[j]
                f[j] = (t + f[j + len]) % Q
                f[j + len] = (zeta * (f[j + len] - t)) % Q

            start += 2 * len

        len *= 2

    return [(felem * 3303) % Q for felem in f]


def base_case_multiply(a0, a1, b0, b1, gamma):
    c0 = a0 * b0 + a1 * b1 * gamma
    c1 = a0 * b1 + a1 * b0

    return c0, c1


def multiply_ntt_s(fc, gc):
    hc = [0] * 256
    for i in range(128):
        hc[2 * i], hc[2 * i + 1] = base_case_multiply(fc[2 * i], fc[2 * i + 1], gc[2 * i], gc[2 * i + 1], GAMMA[i])
    
    return hc


def vector_add(ac, bc):
	return [(x + y) % Q for x, y in zip(ac, bc)]

def vector_sub(ac, bc):
	return [(x - y) % Q for x, y in zip(ac, bc)]


def matrix_array_mult(Ac, uc, k):
    wc = [None for _ in range(len(Ac))]

    for i in range(len(Ac)):
        wc[i] = reduce(vector_add, [multiply_ntt_s(Ac[i][j], uc[j]) for j in range(k)])

    return wc



def k_pke_keygen(k, eta1):
    d = os.urandom(32)
    rho, sigma = G(d)
    N = 0
    Ac = [[None for _ in range(k)] for _ in range(k)]
    s = [None for _ in range(k)]
    e = [None for _ in range(k)]

    for i in range(k):
        for j in range(k):
            Ac[i][j] = sample_ntt(XOF(rho, i, j))

    for i in range(k):
        s[i] = sample_poly_cbd(PRF(eta1, sigma, bytes([N])), eta1)
        N += 1

    for i in range(k):
        e[i] = sample_poly_cbd(PRF(eta1, sigma, bytes([N])), eta1)
        N += 1

    sc = [ntt(s[i]) for i in range(k)]
    ec = [ntt(e[i]) for i in range(k)]
    tc = [reduce(vector_add, [multiply_ntt_s(Ac[i][j], sc[j]) for j in range(k)] + [ec[i]]) for i in range(k)]

    ek_PKE = b"".join(byte_encode(12, tc_elem) for tc_elem in tc) + rho
    dk_PKE = b"".join(byte_encode(12, sc_elem) for sc_elem in sc)

    return ek_PKE, dk_PKE


def transpmatrix_array_mult(Act, uc, k):
    wc = [None for _ in range(len(Act))]

    for i in range(len(Act)):
        wc[i] = reduce(vector_add, [multiply_ntt_s(Act[j][i], uc[j]) for j in range(k)])

    return wc

def transparray_array_mult(uct, vc, k):
    return reduce(vector_add, [multiply_ntt_s(uct[i], vc[i]) for i in range(k)])


def compress(d, x):
	return [(((n * 2**d) + Q // 2 ) // Q) % (2**d) for n in x]

def decompress(d, x):
	return [(((n * Q) + 2**(d-1) ) // 2**d) % Q for n in x]









rand = os.urandom(32)
message = b'Este e um exemplo de mensagem em'
ek_PKE, dk_PKE = k_pke_keygen(3, 2)
#  
print('message:', message)
cipher = k_pke_encrypt(ek_PKE, message, rand, 3, 2, 2)
print(cipher)
# 
message2 = k_pke_decrypt(dk_PKE, cipher, 3)
print('message:', message2)

ek, dk = ml_kem_keygen()
#print('ek:', ek)
#print('dk:', dk)

K, c = ml_kem_encaps(ek)
#print('K:', K)
#print('c:', c)

Kl = ml_kem_decaps(c, dk)
#print(Kl)
