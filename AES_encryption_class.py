#Crypto module needs to install manually -> pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import random

class AES_Cipher:

    def __init__(self, key):
        self.hashObj = SHA256.new(key.encode("utf-8"))
        self.hkey = self.hashObj.digest()


    def encrypt(self, msg, blocksize=16):
        assert blocksize > 2 and blocksize < 256
        last = len(msg) % blocksize
        pad = blocksize - last
        random_pad = bytes(random.sample(range(255), pad-1))
        msg = msg + random_pad + bytes([pad])
        cipher = AES.new(self.hkey,AES.MODE_ECB)
        cipherTxt = cipher.encrypt(msg)
        return cipherTxt

    def decrypt(self, msg): #AES
        decipher = AES.new(self.hkey,AES.MODE_ECB)
        plain = decipher.decrypt(msg)
        original = plain[:-plain[-1]]
        return original

