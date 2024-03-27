from sage.all import *
from sage.rings.finite_rings.integer_mod import IntegerMod_int

def ascii_integer(s):
    result = 0
    for char in s:
        result = result * 100 + ord(char)
    return result


def random_zmod_element(n):
    return IntegerMod_int(1, n-1)

def xor(a,b):
    int_a = int(a)
    int_b = int(b)
    return int_a ^ int_b

