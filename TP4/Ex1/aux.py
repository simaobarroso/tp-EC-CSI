import hashlib  
from sage.all import *

def integer_to_bits(x, alpha):
    y = [0] * alpha
    for i in range(alpha):
        y[i] = x % 2
        x //= 2
    return y

def bits_to_integer(y):
    alpha = len(y)
    x = 0
    for i in range(1, alpha + 1):
        x += y[alpha - i] * 2**(i - 1)
    return x

def bits_to_bytes(y):
    c = len(y)
    num_bytes = ceil(c / 8)
    z = [0] * num_bytes
    for i in range(c):
        z[i // 8] += y[i] * 2**(i % 8)
    return bytes(z)

def bytes_to_bits(z):
    d = len(z)
    y = [0] * (d * 8)
    for i in range(d):
        for j in range(8):
            y[8*i + j] = z[i] % 2
            z[i] //= 2
    return y

def coef_from_three_bytes(b0, b1, b2, q):
    if b2 > 127:
        b2 -= 128 
    z = 2 ** 16 * b2 + 2 ** 8 * b1 + b0
    if z < q:
        return z
    else:
        return None

def coef_from_half_byte(b, eta):
    if eta == 2 and b < 15:
        return 2 - (b % 5)
    elif eta == 4 and b < 9:
        return 4 - b
    else:
        return None

def simple_bit_pack(w, b):
    z = ""
    for i in range(256):
        z += integer_to_bits(w[i], b)
    return bits_to_bytes(z)

def bit_pack(w, a, b):
    z = ""
    for i in range(256):
        z += integer_to_bits(b - w[i], a + b)
    return bits_to_bytes(z)

def bitlen(x):
    return x.nbits()

def simple_bit_unpack(v, b):
    c = bitlen(b)
    z = bytes_to_bits(v)
    w = [0] * 256
    for i in range(256):
        w[i] = bits_to_integer(z[i*c:i*c+c])
    return w

def bit_unpack(v, a, b):
    c = ceil(log(a + b + 1, 2))
    z = bytes_to_bits(v)
    w = []
    for i in range(256):
        wi = b - bits_to_integer(z[i*c:(i+1)*c])
        w.append(wi)
    return w

def hint_bit_pack(h):
    k = len(h)
    omega = sum(1 for hi in h for coeff in hi if coeff == 0)
    y = bytearray(omega + k)
    index = 0
    for i, hi in enumerate(h):
        for j, coeff in enumerate(hi):
            if coeff == 0:
                y[index] = j
                index += 1
        y[omega + i] = index
    return bytes(y)

def hint_bit_unpack(y,k):
    omega = len(y) - k
    h = [0] * k
    index = 0
    for i in range(k):
        if y[omega + i] < index or y[omega + i] > omega:
            return None
        while index < y[omega + i]:
            h[i][y[index]] = 1
            index += 1
    while index < omega:
        if y[index] == 0:
            return None
        index += 1
    return h

def pk_encode(p, t1, q, d):
    pk = bytes_to_bits(p)
    for ti in t1:
        pk += simple_bit_pack(ti, 2 * bitlen(q - 1) - d)
    return bits_to_bytes(pk)

def pk_decode(pk, q, d):
    y0, *z = bytes_to_bits(pk)
    p = bits_to_bytes(y0)
    t1 = []
    for zi in z:
        t1.append(simple_bit_unpack(zi, 2 * bitlen(q - 1) - d))
    return p, t1

def sk_encode(p, K, tr, s1, s2, t0, d, n): 
    sk = bits_to_bytes(p) + bits_to_bytes(K) + bits_to_bytes(tr)
    for si in s1:
        sk += bit_pack(si, n, n)
    for si in s2:
        sk += bit_pack(si, n, n)
    for ti in t0:
        sk += bit_pack(ti, 2**(-d-1), 2**d-1)
    return sk

def sk_decode(sk, d, n, l, k):
    f, g, h, *rest = bytes_to_bits(sk)
    p = bits_to_bytes(f)
    K = bits_to_bytes(g)
    tr = bits_to_bytes(h)
    s1 = [bit_unpack(yi, n, n) for yi in rest[:l]]
    s2 = [bit_unpack(zi, n, n) for zi in rest[l:l+k]]
    t0 = [bit_unpack(wi, 2**(-d-1), 2**d-1) for wi in rest[l+k:l+2*k]]
    return p, K, tr, s1, s2, t0

def sig_encode(c_tilde, z, h, y1):
    σ = bits_to_bytes(c_tilde)
    for zi in z:
        σ += bit_pack(zi, y1 - 1, y1)
    σ += hint_bit_pack(h)
    return σ

def sig_decode(σ, y1):
    w, *x, y = bytes_to_bits(σ)
    c_tilde = bits_to_bytes(w)
    z = [bit_unpack(xi, y1 - 1, y1) for xi in x]
    h = hint_bit_unpack(y)
    return c_tilde, z, h

def w1_encode(w1, q, y2):
    w1_tilde = ()
    for wi in w1:
        w1_tilde += bytes_to_bits(simple_bit_pack(wi, (q - 1) / (2 * y2) - 1))
    return w1_tilde

def expand_a(p, Tq, k, l):
    A_hat = matrix(Tq, k, l)
    for r in range(k):
        for s in range(l):
            A_hat[r, s] = rej_ntt_poly(p + integer_to_bits(s, 8) + integer_to_bits(r, 8))
    return A_hat

def expand_s(p, l, k):
    s1 = [rej_bounded_poly(p + integer_to_bits(r, 16)) for r in range(l)]
    s2 = [rej_bounded_poly(p + integer_to_bits(r + l, 16)) for r in range(k)]
    return (s1, s2)

def power2_round(r, q, d):
    r_plus = r % q
    r0 = r_plus % 2^d
    r1 = (r_plus - r0) / (2^d)
    return (r1, r0)

def decompose(r,q,y2):
    r_plus = r % q
    r0 = r_plus % (2^y2)
    if r_plus - r0 == q - 1:
        r1 = 0
        r0 -= 1
    else:
        r1 = (r_plus - r0) // (2^y2)
    return (r1, r0)

def brv(k, num_bits):
    result = 0
    for i in range(num_bits):
        bit = (k >> i) & 1
        result |= bit << (num_bits - 1 - i)
    
    return result

def ntt_inverse(w_hat, q, eps):
    w = [0] * 256
    for j in range(256):
        w[j] = w_hat[j]
    k = 256
    len = 1
    while len < 256:
        start = 0
        while start < 256:
            k -= 1
            zeta = -eps * brv(k) % q
            for j in range(start, start + len):
                t = w[j]
                w[j] = t + w[j + len]
                w[j + len] = t - w[j + len]
                w[j + len] = zeta * w[j + len]
            start += 2 * len
        len *= 2
    f = 8347681  
    for j in range(256):
        w[j] = f * w[j]
    return w

def montgomery_reduce(a, q):
    QINV = 58728449 
    t = (a % 2^32) * QINV % 2^32
    r = (a - t * q) % q
    return r

def sample_in_ball(seed, tau, q):
    c = PolynomialRing(Zmod(q), 'x').zero()
    k = 8
    for i in range(256 - tau, 256):
        while hashlib.sha256(seed + str(k).encode()).digest()[0] > i:
            k += 1
        j = hashlib.sha256(seed + str(k).encode()).digest()[0] 
        c[j] = (-1) ** (hashlib.sha256(seed + str(i - 256).encode()).digest()[0])
        k += 1
    return c

def expand_mask(seed, mu, ell, gamma_1):
    c = [None] * ell
    for r in range(ell):
        n = '{0:016b}'.format(mu + r)
        v = [hashlib.sha256(seed + n.encode()).digest()[i] for i in range(32 * r, 32 * (r + 1))]
        c[r] = Integer(bitstring=v, signed=True).bitslice(0, gamma_1)
    return c

def high_bits(poly):
    return poly.coefficients(sparse=False)[0]

def low_bits(poly):
    return poly.coefficients(sparse=False)[-1]

def make_hint(z, r):
    r1 = high_bits(r)
    v1 = high_bits(r + z)
    return r1 == v1

def use_hint(h, r, q, gamma_2):
    m = (q - 1) // (2 * gamma_2)
    r1 = high_bits(r)
    r0 = low_bits(r)
    if h and r0 > 0:
        return (r1 + 1) % m
    elif h and r0 <= 0:
        return (r1 - 1) % m
    else:
        return r1

def ntt(poly, q, omega):
    if omega is None:
        omega = primitive_root(q)
    n = poly.degree() + 1
    w_hat = poly.list()[:]  

    k = 0
    length = n // 2
    while length >= 1:
        start = 0
        while start < n:
            k += 1
            zeta = omega ** ((q - 1) // length)
            for j in range(start, start + length):
                t = zeta * w_hat[j + length] % q
                w_hat[j + length] = (w_hat[j] - t) % q
                w_hat[j] = (w_hat[j] + t) % q
            start += 2 * length
        length //= 2

    return w_hat

def rej_bounded_poly(seed, q, eta):
    a = PolynomialRing(Zmod(q), 'x').zero()
    j = 0
    c = 0
    while j < 256:
        z = hashlib.sha256(seed + str(c).encode()).digest()
        z0 = coef_from_half_byte(z[0] % 16, eta)
        z1 = coef_from_half_byte(z[0] // 16, eta)
        if z0 is not None:
            a[j] = z0
            j += 1
        if z1 is not None and j < 256:
            a[j] = z1
            j += 1
        c += 1
    return a

def rej_ntt_poly(seed, q):
    a_hat = ntt(PolynomialRing(Zmod(q), 'x').zero())
    j = 0
    c = 0
    while j < 256:
        a_hat[j] = coef_from_three_bytes(hashlib.sha256(seed + str(c).encode()).digest())
        c += 3
        if a_hat[j] is not None:
            j += 1
    return a_hat
