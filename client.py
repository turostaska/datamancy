import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
from utils import *

netif = init_network(client_addr)

def read_rsa_public_key():
    global public_key
    if os.path.exists(public_key_path):
        with open(public_key_path, 'rb') as f:
            return RSA.import_key(f.read())


def send_session_init(username, password, dest=server_addr):
    header = types['session_init'] + bytes([98])
    session_key = Random.get_random_bytes(32)

    body = pad_to_length(username, 32) + pad_to_length(password, 32) + session_key

    key = read_rsa_public_key()
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(header+body)

    protocol_state = ProtocolState(states['WAITING'], session_key, None)
    netif.send_msg(dest, ciphertext)



def send_gcm_message():
    session_key = Random.get_random_bytes(32)
    # nonce = Random.get_random_bytes(16)
    # cipher = AES.new(key=session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)
    #
    # ciphertext, tag = cipher.encrypt_and_digest(header + body)
    #
    # crypto_fields = tag + nonce
    # data = ciphertext + crypto_fields


def main():
    username = 'amyglassires'  # input('Please enter your username: ')
    password = 'afraidofuntruecops'  # input("Password: ")
    # todo: átírni getpassra
    # password = getpass("Password: ")
    send_session_init(username.encode(), password.encode())
    _, msg = netif.receive_msg(blocking=True)
    process_session_accept(msg)


if __name__ == '__main__':
    main()
