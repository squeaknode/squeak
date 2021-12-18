# MIT License
#
# Copyright (c) 2020 Jonathan Zernik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from ecpy import ecrand
from ecpy.curves import Curve


CURVE = Curve.get_curve('secp256k1')


def generate_random_scalar():
    order = CURVE.order
    return ecrand.rnd(order)


def scalar_to_bytes(s):
    return s.to_bytes(32, byteorder='big')


def scalar_from_bytes(b):
    return int.from_bytes(b, 'big')


def scalar_sum(x, y):
    order = CURVE.order
    return (x + y) % order


def scalar_difference(x, y):
    order = CURVE.order
    return (x - y) % order


def generate_secret_key():
    s = generate_random_scalar()
    return scalar_to_bytes(s)


# def generate_secret_key():
#     # Generate random message
#     # msg = os.urandom(KEY_LENGTH)
#     msg = int(0x0101010101010101010101010101010101010101010101010101010101010101)
#     msg = msg.to_bytes(32,'big')

#     # Generate key pair
#     # x = os.urandom(KEY_LENGTH)
#     cv = Curve.get_curve('secp256k1')
#     pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
#                                0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
#                                cv))
#     pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
#                           cv)

#     # Generate random nonce
#     # k = int.from_bytes(os.urandom(KEY_LENGTH), 'big')
#     k = int(0x4242424242424242424242424242424242424242424242424242424242424242)

#     # Calculate signature
#     signer = ECSchnorr(hashlib.sha256,"LIBSECP","ITUPLE")
#     sig = signer.sign_k(msg,pv_key,k)

#     # Verify the signature
#     expect_r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
#     expect_s = 0xacd417b277ab7e7d993cc4a601dd01a71696fd0dd2e93561d9de9b69dd4dc75c
#     r, s = sig
#     s_hex = "{:64x}".format(s)
#     assert(expect_r == r)
#     assert(expect_s == s)
#     assert(signer.verify(msg,sig,pu_key))
#     return bytes.fromhex(s_hex)


def payment_point_from_scalar(s):
    G = CURVE.generator
    return s*G


def payment_point_to_bytes(payment_point):
    return bytes(CURVE.encode_point(payment_point, compressed=True))


def bytes_to_payment_point(point_bytes):
    return CURVE.decode_point(point_bytes)


def payment_point_bytes_from_scalar_bytes(s_bytes):
    s = scalar_from_bytes(s_bytes)
    payment_point = payment_point_from_scalar(s)
    return payment_point_to_bytes(payment_point)


# def payment_point_from_secret_key(secret_key):
#     G = CURVE.generator
#     s = int.from_bytes(secret_key, 'big')
#     payment_point = s*G
#     return bytes(CURVE.encode_point(payment_point, compressed=True))
