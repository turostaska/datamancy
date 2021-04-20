import os
import struct
from collections import namedtuple
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
from utils import *
from getpass import getpass

own_addr = 'B'
netif = init_network(own_addr)

def read_rsa_public_key():
    global public_key
    if os.path.exists(public_key_path):
        with open(public_key_path, 'rb') as f:
            return RSA.import_key(f.read())


def send_session_init(username, password, dest=server_addr):
    global protocol_state

    header = types['session_init'] + bytes([99])
    session_key = Random.get_random_bytes(32)

    body = pad_to_length(username, 32) + pad_to_length(password, 32) + session_key + own_addr.encode()

    key = read_rsa_public_key()
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(header+body)

    protocol_state = ProtocolState(states['WAITING'], session_key, None)
    netif.send_msg(dest, ciphertext)


def process_session_accept(data):
    global protocol_state

    ciphertext = data[:1]
    tag = data[1:17]
    nonce = data[17:33]

    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    body = cipher.decrypt_and_verify(ciphertext, tag)

    if body == types['session_accept']:
        protocol_state = ProtocolState(states['ACTIVE'], protocol_state.session_key, -1)
        return True


def send_request(cmd, body):
    global protocol_state
    protocol_state = ProtocolState(protocol_state.state, protocol_state.session_key, protocol_state.sqn+1)

    type = types['request']
    timestamp = bytearray(struct.pack("d", datetime.now().timestamp()))
    sequence_number = protocol_state.sqn.to_bytes(4, byteorder="big")

    length = (len(type) + 8 + 8 + len(sequence_number) + len(cmd) + len(body) + 16 + 16).to_bytes(8, byteorder="big")
    header = type + length + timestamp + sequence_number + cmd.encode()

    nonce = Random.get_random_bytes(16)
    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    ciphertext, tag = cipher.encrypt_and_digest(header + body.encode())

    crypto_fields = tag + nonce
    data = ciphertext + crypto_fields

    netif.send_msg(server_addr, data)

states = {'WAITING': 1, 'ACTIVE': 2}
ProtocolState = namedtuple('State', ['state', 'session_key', 'sqn'])
protocol_state = ProtocolState(states['WAITING'], None, None)

def main():
    username = 'amyglassires'  # input('Please enter your username: ')
    password = 'afraidofuntruecops'  # input("Password: ")
    # todo: átírni getpassra
    # password = getpass("Password: ")
    send_session_init(username.encode(), password.encode())

    _, msg = netif.receive_msg(blocking=True)
    if not process_session_accept(msg):
        print('Login failed.')
        return

    send_request('ASD', 'megeszem a gcm, ezert hivnak jedinek')


if __name__ == '__main__':
    main()
