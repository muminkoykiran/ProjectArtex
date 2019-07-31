from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from hashlib import md5


class CryptoStuff:
    def __init__(self):
        self.BLOCK_SIZE = 16

    def pad(self, data):
        length = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        return data + (chr(length)*length).encode().decode('ascii')

    def unpad(self, data):
        return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

    def bytes_to_key(self, data, salt, output=48):
        # extended from https://gist.github.com/gsakkis/4546068
        assert len(salt) == 8, len(salt)
        data += salt
        key = md5(data).digest()
        final_key = key
        while len(final_key) < output:
            key = md5(key + data).digest()
            final_key += key
        return final_key[:output]

    def encrypt(self, message, passphrase):
        salt = Random.new().read(8)
        key_iv = self.bytes_to_key(passphrase, salt, 32+16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        return b64encode(b"Salted__" + salt + aes.encrypt(self.pad(message)))

    def decrypt(self, encrypted, passphrase):
        encrypted = b64decode(encrypted)
        assert encrypted[0:8] == b"Salted__"
        salt = encrypted[8:16]
        key_iv = self.bytes_to_key(passphrase, salt, 32+16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(aes.decrypt(encrypted[16:]))
