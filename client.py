import os
import struct
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
from utils import *
from getpass import getpass

class ProtocolState:
    def __init__(self, state=None, session_key=None, req_sqn=None, resp_sqn=None, working_dir=None):
        self.state = state
        self.session_key = session_key
        self.req_sqn = req_sqn
        self.resp_sqn = resp_sqn
        self.working_dir = working_dir


states = {'WAITING': 1, 'ACTIVE': 2}
protocol_state = ProtocolState(states['WAITING'])
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

    protocol_state.state=states['WAITING']
    protocol_state.session_key=session_key
    netif.send_msg(dest, ciphertext)


def process_session_accept(data):
    global protocol_state

    ciphertext = data[:1]
    tag = data[1:17]
    nonce = data[17:33]

    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    body = cipher.decrypt_and_verify(ciphertext, tag)

    if body == types['session_accept']:
        protocol_state.state = states['ACTIVE']
        protocol_state.req_sqn = -1
        protocol_state.resp_sqn = -1
        return True

def send_request(cmd, body):
    global protocol_state
    protocol_state.req_sqn += 1

    type = types['request']
    timestamp = bytearray(struct.pack("d", datetime.now().timestamp()))
    sequence_number = protocol_state.req_sqn.to_bytes(4, byteorder="big")

    length = (len(type) + 8 + 8 + len(sequence_number) + len(cmd) + len(body) + 16 + 16).to_bytes(8, byteorder="big")
    header = type + length + timestamp + sequence_number + cmd.encode()

    nonce = Random.get_random_bytes(16)
    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    ciphertext, tag = cipher.encrypt_and_digest(header + body)

    crypto_fields = tag + nonce
    data = ciphertext + crypto_fields

    netif.send_msg(server_addr, data)

def process_response(msg):
        tag = msg[-32:-16]
        nonce = msg[-16:]
        ciphertext = msg[0:-32]

        cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        type = data[:1]
        length = int.from_bytes(data[1:9], byteorder='big')
        timestamp = struct.unpack("d", data[9:17])[0]
        sqn = int.from_bytes(data[17:21], byteorder='big')
        cmd = data[21:24].decode('utf8').upper()
        req_sqn = int.from_bytes(data[24:28], byteorder="big")
        body = data[28:]

        if type != types['response']:
            print(f"Invalid type, got {type}")
            # send_error(sqn)
            return
        if sqn != protocol_state.resp_sqn + 1:
            print(f"Expected sequence number {protocol_state.resp_sqn}, but got {sqn}")
            # send_error(sqn)
            return
        if req_sqn != protocol_state.req_sqn:
            print(f"Expected response for request {protocol_state.req_sqn}, but got {req_sqn}")
            # send_error(sqn)
            return
        if timestamp > datetime.now().timestamp() or timestamp < datetime.now().timestamp() - 60:
            print(f'Untrue timestamp: {timestamp}')
            # send_error(sqn)
            return
        if length != len(msg):
            print("Invalid message length")
            # send_error(sqn)
            return

        # print(len(body))
        # filename = body[:255]
        # filename = remove_padding(filename).decode('utf8')
        # file = body[255:]
        # protocol_state.resp_sqn += 1
        # print(filename)
        # with open(filename, "wb") as out_file:
        #     out_file.write(file)
        print(body.decode())

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

    # send_request('DNL', 'magan.png'.encode())
    # _, msg = netif.receive_msg(blocking=True)
    # process_response(msg)

    with open(os.path.join("magan.png"), "rb") as in_file:
        data = in_file.read()

    send_request('UPL', pad_to_length("magan.png".encode(), 255) + data)
    _, msg = netif.receive_msg(blocking=True)
    process_response(msg)

if __name__ == '__main__':
    main()
