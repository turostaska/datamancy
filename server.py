import struct
from datetime import datetime

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256

from utils import *
import os.path
from collections import namedtuple
from Crypto.PublicKey import RSA


private_key_path = './private-key'
key_pair = None
netif = init_network(server_addr)
users = {}
states = {'WAITING': 1, 'ACTIVE': 2}
ProtocolState = namedtuple('State', ['state', 'session_key', 'sqn', 'addr'])
protocol_state = ProtocolState(states['WAITING'], None, None, None)


def auth_client(ciphertext):
    cipher = PKCS1_OAEP.new(key_pair)
    data = cipher.decrypt(ciphertext)

    type = data[:1]
    if type != types['session_init']:
        print("Invalid message in this state! Awaiting session_init!")
        return

    len = data[1:2]
    if int.from_bytes(len, "big") != 99:
        print("Invalid message length")
        return

    username_padded = data[2:34]
    password_padded = data[34:66]
    session_key_padded = data[66:98]
    addr = data[98:99].decode('utf8')

    username = remove_padding(username_padded)
    password = remove_padding(password_padded)
    session_key = remove_padding(session_key_padded)

    print(username.decode('utf8'))
    print(password.decode('utf8'))
    print(session_key)

    hash = SHA256.new()
    hash.update(password)
    password_hashed = hash.digest()
    return users[username.decode('utf8')] == password_hashed, session_key, addr


def generate_rsa_keys():
    global key_pair
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, 'rb') as f:
            key_pair = RSA.import_key(f.read())
            print(key_pair.export_key())
        return

    key_pair = RSA.generate(2048)
    with open(private_key_path, 'wb') as f:
        f.write(key_pair.export_key('DER'))
    with open(public_key_path, 'wb') as f:
        f.write(key_pair.public_key().export_key('DER'))


def read_users():
    with open(users_path, 'rb') as f:
        while True:
            username = f.readline()
            password = f.read(33)
            if not username:
                break
            users[(username.decode('utf8')).replace('\n', '')] = password[0:32]



def send_session_accept(dest=protocol_state.addr):
    nonce = Random.get_random_bytes(16)
    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    body = types['session_accept']
    ciphertext, tag = cipher.encrypt_and_digest(body)

    crypto_fields = tag + nonce
    data = ciphertext + crypto_fields

    netif.send_msg(dest, data)


def send_error(sqn):
    sqn -= 1
    # todo: send an error msg responding to the untrue call
    pass


def process_request(msg):
    # global protocol_state
    # protocol_state = ProtocolState(protocol_state.state, protocol_state.session_key, protocol_state.sqn + 1, protocol_state.addr)

    tag = msg[-32:-16]
    nonce = msg[-16:]
    ciphertext = msg[0:-32]

    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)
    data = cipher.decrypt_and_verify(ciphertext, tag).decode('utf8')

    type = data[0]
    length = int.from_bytes(data[1:9], byteorder='big')
    timestamp = struct.unpack("d", data[9:17])[0]
    sqn = int.from_bytes(data[17:21], byteorder='big')
    cmd = data[21:24]
    body = data[24:].decode('utf8')

    if type != types['request']:
        print("Invalid type")
        send_error(sqn)
        return
    if sqn != protocol_state.sqn+1:
        print(f"Expected sequence number {protocol_state.sqn}, but got {sqn}")
        send_error(sqn)
        return
    if timestamp > datetime.now().timestamp() or timestamp < datetime.now().timestamp() - datetime.timedelta(minutes=1):
        print(f'Untrue timestamp: {timestamp}')
        send_error(sqn)
        return
    if length != len(msg):
        print("Invalid message length")
        send_error(sqn)
        return
    # todo: manage request



def send_gcm_msg():
    type = types['response']
    pass


def main():
    generate_rsa_keys()
    read_users()

    global protocol_state
    while protocol_state.state == states['WAITING']:
        _, msg = netif.receive_msg(blocking=True)
        auth_status, session_key, addr = auth_client(msg)
        print(f"Successful login from address {addr}" if auth_status else "Login rejected")
        if auth_status:
            protocol_state = ProtocolState(states['ACTIVE'], session_key, -1, addr)
            send_session_accept(addr)

    while protocol_state.state == states['ACTIVE']:
        _, msg = netif.receive_msg(blocking=True)
        process_request(msg)


if __name__ == '__main__':
    main()

