from ecpy.ecschnorr import ECSchnorr
from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey

import hashlib


CURVE = Curve.get_curve('secp256k1')


def generate_secret_key():
    # Generate random message
    # msg = os.urandom(KEY_LENGTH)
    msg = int(0x0101010101010101010101010101010101010101010101010101010101010101)
    msg = msg.to_bytes(32,'big')

    # Generate key pair
    # x = os.urandom(KEY_LENGTH)
    cv = Curve.get_curve('secp256k1')
    pu_key = ECPublicKey(Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
                               0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
                               cv))
    pv_key = ECPrivateKey(0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5,
                          cv)

    # Generate random nonce
    # k = int.from_bytes(os.urandom(KEY_LENGTH), 'big')
    k = int(0x4242424242424242424242424242424242424242424242424242424242424242)

    # Calculate signature
    signer = ECSchnorr(hashlib.sha256,"LIBSECP","ITUPLE")
    sig = signer.sign_k(msg,pv_key,k)

    # Verify the signature
    expect_r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
    expect_s = 0xacd417b277ab7e7d993cc4a601dd01a71696fd0dd2e93561d9de9b69dd4dc75c
    r, s = sig
    s_hex = "{:64x}".format(s)
    assert(expect_r == r)
    assert(expect_s == s)
    assert(signer.verify(msg,sig,pu_key))
    return bytes.fromhex(s_hex)


def payment_point_from_secret_key(secret_key):
    G = CURVE.generator
    s_hex = secret_key.hex()
    s = int(s_hex, 16)
    payment_point = s*G
    return bytes(CURVE.encode_point(payment_point, compressed=True))
