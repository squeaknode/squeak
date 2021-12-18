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
from squeak.core.encryption import _create_data_cipher
from squeak.core.encryption import CIPHER_BLOCK_LENGTH
from squeak.core.encryption import decrypt_content
from squeak.core.encryption import encrypt_content
from squeak.core.encryption import generate_data_key
from squeak.core.encryption import generate_initialization_vector


PREIMAGE_LENGTH = 32


class TestEncryptionCipher(object):

    def test_cipher_block_size(self):
        data_key = generate_data_key()
        initialization_vector = generate_initialization_vector()
        cipher = _create_data_cipher(data_key, initialization_vector)

        assert cipher.algorithm.block_size == CIPHER_BLOCK_LENGTH * 8


class TestEncryptContent(object):

    def test_encrypt_decrypt(self):
        data_key = generate_data_key()
        initialization_vector = generate_initialization_vector()
        message = b"encrypted data"

        encrypted_msg = encrypt_content(data_key, initialization_vector, message)
        decrypted_msg = decrypt_content(data_key, initialization_vector, encrypted_msg)

        assert decrypted_msg == message
