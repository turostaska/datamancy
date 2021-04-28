import os
import struct
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA3_256
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
hashed_passw = None


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
    ciphertext = cipher.encrypt(header + body)

    protocol_state.state = states['WAITING']
    protocol_state.session_key = session_key
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
        return
    if sqn != protocol_state.resp_sqn + 1:
        print(f"Expected sequence number {protocol_state.resp_sqn}, but got {sqn}")
        return
    if req_sqn != protocol_state.req_sqn:
        print(f"Expected response for request {protocol_state.req_sqn}, but got {req_sqn}")
        return
    if timestamp > datetime.now().timestamp() or timestamp < datetime.now().timestamp() - 60:
        print(f'Untrue timestamp: {timestamp}')
        return
    if length != len(msg):
        print("Invalid message length")
        return

    protocol_state.resp_sqn += 1

    if cmd == 'MKD':
        if body == result['success']:
            print('Directory created.')
        else:
            print('Creating directory failed.')
    elif cmd == 'RMD':
        if body == result['success']:
            print('Directory removed.')
        else:
            print('Removing directory failed.')
    elif cmd == 'GWD':
        print(body.decode())
    elif cmd == 'CWD':
        if body == result['success']:
            print('Directory changed.')
        else:
            print('Changing directory failed.')
    elif cmd == 'LST':
        print(body.decode())
    elif cmd == 'UPL':
        if body == result['success']:
            print('Upload was successful.')
        else:
            print('Upload failed.')
    elif cmd == 'DNL':
        if body == result['failure']:
            print("Download failed.")
        else:
            filename = body[:255]
            filename = remove_padding(filename).decode('utf8')
            encrypted_file = body[255:]
            file = decrypt_file(encrypted_file)
            with open(filename, "wb") as out_file:
                out_file.write(file)
            print(f'Successfully downloaded {filename}')
    elif cmd == 'RMF':
        if body == result['success']:
            print('File deleted.')
        else:
            print('File deletion failed.')


def store_hashed_pwd(passwd):
    global hashed_passw
    hash = SHA3_256.new()
    hash.update(passwd.encode())
    hashed_passw = hash.digest()


def encrypt_file(file):
    global hashed_passw
    key = hashed_passw

    nonce = Random.get_random_bytes(16)
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    ciphertext, tag = cipher.encrypt_and_digest(file)

    crypto_fields = tag + nonce
    data = ciphertext + crypto_fields

    return data


def decrypt_file(file):
    global hashed_passw
    key = hashed_passw

    tag = file[-32:-16]
    nonce = file[-16:]
    ciphertext = file[0:-32]

    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    return data


def main():
    username = input('Please enter your username: ')
    password = getpass("Password: ")
    send_session_init(username.encode(), password.encode())

    store_hashed_pwd(password)
    password = None

    _, msg = netif.receive_msg(blocking=True)
    if not process_session_accept(msg):
        print('Login failed.')
        return

    while True:
        line = input('Awaiting command: ')
        parts = line.split(' ', 1)

        cmd = parts[0].upper()
        if cmd == 'MKD':
            body = pad_to_length(parts[1].encode(),255)
        elif cmd == 'RMD':
            body = pad_to_length(parts[1].encode(),255)
        elif cmd == 'GWD':
            body = "".encode()
        elif cmd == 'CWD':
            body = pad_to_length(parts[1].encode(),255)
        elif cmd == 'LST':
            body = "".encode()
        elif cmd == 'UPL':
            filename = parts[1]
            try:
                with open(os.path.join(os.getcwd(), filename), "rb") as in_file:
                    file = in_file.read()
                    encrypted_file = encrypt_file(file)
            except:
                print(f'File not found: {filename}')
                continue
            body = pad_to_length(filename.encode(),255) + encrypted_file
        elif cmd == 'DNL':
            body = pad_to_length(parts[1].encode(),255)
        elif cmd == 'RMF':
            body = pad_to_length(parts[1].encode(),255)
        else:
            print('Wrong command.')
            continue

        send_request(cmd, body)
        _, msg = netif.receive_msg(blocking=True)
        process_response(msg)


if __name__ == '__main__':
    main()
