## Modified with reference: https://github.com/mCodingLLC/VideosSampleCode/blob/master/videos/064_md5_a_broken_secure_hash_algorithm_python_implementation/md5.py

from io import BytesIO
from typing import BinaryIO

import numpy as np
from argparse import ArgumentParser


from utils import F, G, H, I
from utils import left_rotate


MD5_BLOCK_SIZE = 64

# SHIFT settings
SHIFT = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# Sines
SINES = np.abs(np.sin(np.arange(64) + 1))  # "nothing up my sleeve" randomness
SINE_RANDOMNESS = [int(x) for x in np.floor(2 ** 32 * SINES)]

# MIXER
MIXER_FOR_STEP = [F for _ in range(
    16)] + [G for _ in range(16)] + [H for _ in range(16)] + [I for _ in range(16)]


# These are all permutations of [0, ..., 15].
# [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
round_1_perm = [i for i in range(16)]
# [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
round_2_perm = [(5 * i + 1) % 16 for i in range(16)]
# [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2]
round_3_perm = [(3 * i + 5) % 16 for i in range(16)]
# [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]
round_4_perm = [(7 * i) % 16 for i in range(16)]
MSG_IDX_FOR_STEP = round_1_perm + round_2_perm + round_3_perm + round_4_perm


class MD5State(object):
    def __init__(self):

        self.length: int = 0
        self.state: tuple[int, int, int, int] = (
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        self.n_filled_bytes: int = 0
        self.buf: bytearray = bytearray(MD5_BLOCK_SIZE)

    def digest(self) -> bytes:

        return b''.join(x.to_bytes(length=4, byteorder='little') for x in self.state)

    def hex_digest(self) -> str:

        return self.digest().hex()

    def process(self, stream: BinaryIO) -> None:

        assert self.n_filled_bytes < len(self.buf)

        view = memoryview(self.buf)
        while bytes_read := stream.read(MD5_BLOCK_SIZE - self.n_filled_bytes):
            view[self.n_filled_bytes:self.n_filled_bytes +
                 len(bytes_read)] = bytes_read
            if self.n_filled_bytes == 0 and len(bytes_read) == MD5_BLOCK_SIZE:
                self.compress(self.buf)
                self.length += MD5_BLOCK_SIZE
            else:
                self.n_filled_bytes += len(bytes_read)
                if self.n_filled_bytes == MD5_BLOCK_SIZE:
                    self.compress(self.buf)
                    self.length += MD5_BLOCK_SIZE
                    self.n_filled_bytes = 0

    def finalize(self) -> None:

        assert self.n_filled_bytes < MD5_BLOCK_SIZE

        self.length += self.n_filled_bytes
        self.buf[self.n_filled_bytes] = 0b10000000
        self.n_filled_bytes += 1

        n_bytes_needed_for_len = 8

        if self.n_filled_bytes + n_bytes_needed_for_len > MD5_BLOCK_SIZE:
            self.buf[self.n_filled_bytes:] = bytes(
                MD5_BLOCK_SIZE - self.n_filled_bytes)
            self.compress(self.buf)
            self.n_filled_bytes = 0

        self.buf[self.n_filled_bytes:] = bytes(
            MD5_BLOCK_SIZE - self.n_filled_bytes)
        bit_len_64 = (self.length * 8) % (2 ** 64)
        self.buf[-n_bytes_needed_for_len:] = bit_len_64.to_bytes(length=n_bytes_needed_for_len,
                                                                 byteorder='little')
        self.compress(self.buf)

    def compress(self, msg_chunk: bytearray) -> None:
        assert len(msg_chunk) == MD5_BLOCK_SIZE  # 64 bytes, 512 bits
        msg_ints = [int.from_bytes(msg_chunk[i:i + 4], byteorder='little')
                    for i in range(0, MD5_BLOCK_SIZE, 4)]
        assert len(msg_ints) == 16

        a, b, c, d = self.state

        for i in range(MD5_BLOCK_SIZE):
            bit_mixer = MIXER_FOR_STEP[i]
            msg_idx = MSG_IDX_FOR_STEP[i]
            a = (a + bit_mixer(b, c, d) +
                 msg_ints[msg_idx] + SINE_RANDOMNESS[i]) % (2 ** 32)
            a = left_rotate(a, SHIFT[i])
            a = (a + b) % (2 ** 32)
            a, b, c, d = d, a, b, c

        self.state = (
            (self.state[0] + a) % (2 ** 32),
            (self.state[1] + b) % (2 ** 32),
            (self.state[2] + c) % (2 ** 32),
            (self.state[3] + d) % (2 ** 32),
        )


def md5(s: bytes) -> bytes:
    state = MD5State()
    state.process(BytesIO(s))
    state.finalize()
    return state.digest()


def md5_string(s: str) -> bytes:
    encoded_str = s.encode()
    return md5(encoded_str)


def md5_file(file: BinaryIO) -> bytes:
    state = MD5State()
    state.process(file)
    state.finalize()
    return state.digest()


if __name__ == '__main__':

    arg_parser = ArgumentParser(
        description="Compute the MD5 hash of a given the string.",
    )
    arg_parser.add_argument("string", type=str)
    args = arg_parser.parse_args()

    md5_hash = md5_string(args.string).hex()
    print(md5_hash)

