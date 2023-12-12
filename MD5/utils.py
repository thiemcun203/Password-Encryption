def left_rotate(x: int, y: int) -> int:
    return ((x << (y & 31)) | ((x & 0xffffffff) >> (32-(y & 31)))) & 0xffffffff

def bit_not(x: int) -> int:
    return 4294967295 - x

#mixing functions

def F(b: int, c: int, d: int) -> int:
    return d ^ (b & (c ^ d))


def G(b: int, c: int, d: int) -> int:
    return c ^ (d & (b ^ c))


def H(b: int, c: int, d: int) -> int:
    return b ^ c ^ d


def I(b: int, c: int, d: int) -> int:
    return c ^ (b | bit_not(d))