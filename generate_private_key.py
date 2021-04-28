from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from utils import *

master_password = 'iamnotanuntruecopiswear'


def generate_and_save_rsa_keys():
    hash = SHA256.new()
    hash.update(master_password.encode())
    password_hashed = hash.digest()

    key_pair = RSA.generate(2048)
    with open(private_key_path, 'wb') as f:
        nonce = Random.get_random_bytes(16)
        cipher = AES.new(key=password_hashed, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

        ciphertext, tag = cipher.encrypt_and_digest(key_pair.export_key('DER'))

        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)
    with open(public_key_path, 'wb') as f:
        f.write(key_pair.public_key().export_key('DER'))


generate_and_save_rsa_keys()