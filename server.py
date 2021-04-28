from datetime import datetime
import struct
from getpass import getpass

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256

from utils import *
import os.path
from Crypto.PublicKey import RSA
import traceback


class ProtocolState:
    def __init__(self, state=None, session_key=None, req_sqn=None, resp_sqn=None, addr=None, username=None,
                 working_dir=None):
        self.state = state
        self.session_key = session_key
        self.req_sqn = req_sqn
        self.resp_sqn = resp_sqn
        self.addr = addr
        self.username = username
        self.working_dir = working_dir


private_key_path = './private-key'
key_pair = None
netif = init_network(server_addr)
users = {}
states = {'WAITING': 1, 'ACTIVE': 2}

protocol_state = ProtocolState(state=states['WAITING'])


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

    username = remove_padding(username_padded).decode("utf8")
    password = remove_padding(password_padded)
    session_key = remove_padding(session_key_padded)

    print(username)
    print(password.decode('utf8'))
    print(session_key)

    hash = SHA256.new()
    hash.update(password)
    password_hashed = hash.digest()
    return users[username] == password_hashed, session_key, addr, username


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

    if not os.path.isdir(protocol_state.working_dir):
        os.mkdir(protocol_state.working_dir)

    netif.send_msg(dest, data)


def send_response(cmd, req_sqn, body):
    protocol_state.resp_sqn += 1

    type = types['response']
    timestamp = bytearray(struct.pack("d", datetime.now().timestamp()))
    sequence_number = protocol_state.resp_sqn.to_bytes(4, byteorder="big")
    request_sequence_number = req_sqn.to_bytes(4, byteorder="big")

    length = (len(type) + 8 + 8 + len(sequence_number) + len(cmd) + len(request_sequence_number) + len(
        body) + 16 + 16).to_bytes(8, byteorder="big")
    header = type + length + timestamp + sequence_number + cmd.encode() + request_sequence_number

    nonce = Random.get_random_bytes(16)
    cipher = AES.new(key=protocol_state.session_key, mode=AES.MODE_GCM, nonce=nonce, mac_len=16)

    ciphertext, tag = cipher.encrypt_and_digest(header + body)

    crypto_fields = tag + nonce
    data = ciphertext + crypto_fields

    netif.send_msg(protocol_state.addr, data)



def mkd(folder_name: str):
    if not check_path_in_scope(folder_name):
        print(f'Path is out of scope')
        send_response("MKD", protocol_state.req_sqn, result['failure'])
        return
    try:
        if not os.path.isdir(append_to_user_path(protocol_state.working_dir, folder_name)):
            os.mkdir(append_to_user_path(protocol_state.working_dir, folder_name))
        else:
            print(f'Directory already exists.')
            send_response("MKD", protocol_state.req_sqn, result['failure'])
            return
    except:
        print(f'Making directory failed.')
        send_response("MKD", protocol_state.req_sqn, result['failure'])
        return

    send_response("MKD", protocol_state.req_sqn, types['success'])


def rmd(folder_name: str):
    if '.' in folder_name or os.path.sep in folder_name:
        print(f'Folder name contained illegal character.')
        send_response("RMD", protocol_state.req_sqn, types['failure'])
        return
    try:
        if os.path.isdir(append_to_user_path(protocol_state.working_dir, folder_name)):
            os.rmdir(append_to_user_path(protocol_state.working_dir, folder_name))
        else:
            print(f'Directory does not exist.')
            send_response("RMD", protocol_state.req_sqn, result['failure'])
            return
    except:
        print('Folder was not empty during deletion.')
        send_response("RMD", protocol_state.req_sqn, result['failure'])
        return
    send_response("RMD", protocol_state.req_sqn, result['success'])


def gwd():
    send_response('GWD', protocol_state.req_sqn, os.path.relpath(protocol_state.working_dir, os.getcwd()).encode())


def cwd(folder_name):
    desired_path = os.path.abspath(os.path.join(protocol_state.working_dir, folder_name))
    if not check_path_in_scope(folder_name):
        print(f'Folder falls out of scope: {desired_path}.')
        send_response("CWD", protocol_state.req_sqn, result['failure'])
        return
    if not os.path.isdir(append_to_user_path(protocol_state.working_dir, folder_name)):
        print(f'Folder does not exist: {desired_path}')
        send_response("CWD", protocol_state.req_sqn, result['failure'])
        return
    protocol_state.working_dir = desired_path
    send_response('CWD', protocol_state.req_sqn, result['success'])


def lst():
    msg = ''
    for dir in os.listdir(protocol_state.working_dir):
        msg += dir + '\n'
    send_response('LST', protocol_state.req_sqn, msg.encode())


def upl(filename, file):
    try:
        with open(os.path.join(protocol_state.working_dir, remove_padding(filename).decode()), "wb") as out_file:
            out_file.write(file)
    except:
        traceback.print_exc()
        send_response('UPL', protocol_state.req_sqn, result['failure'])


def dnl(filename):
    try:
        with open(os.path.join(protocol_state.working_dir, filename), "rb") as in_file:
            data = in_file.read()
            send_response('DNL', protocol_state.req_sqn, result['success'])
    except:
        send_response('DNL', protocol_state.req_sqn, result['failure'])


def rmf(file_name):
    if not check_path_in_scope(file_name):
        print(f'Path is out of scope')
        send_response("RMF", protocol_state.req_sqn, result['failure'])
        return
    if os.path.isfile(append_to_user_path(protocol_state.working_dir, file_name)):
        os.remove(append_to_user_path(protocol_state.working_dir, file_name))
    send_response("RMF", protocol_state.req_sqn, result['success'])


def process_request(msg):
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
    body = data[24:]

    if type != types['request']:
        print(f"Invalid type, got {type}")
        return
    if sqn != protocol_state.req_sqn + 1:
        print(f"Expected sequence number {protocol_state.req_sqn}, but got {sqn}")
        return
    if timestamp > datetime.now().timestamp() or timestamp < datetime.now().timestamp() - 60:
        print(f'Untrue timestamp: {timestamp}')
        return
    if length != len(msg):
        print("Invalid message length")
        return

    if cmd not in ['MKD', 'RMD', 'GWD', 'CWD', 'LST', 'UPL', 'DNL', 'RMF']:
        print(f"Invalid command: {cmd}")
        return

    protocol_state.req_sqn += 1

    if cmd == 'MKD':
        mkd(body.decode("utf8"))
    elif cmd == 'RMD':
        rmd(body.decode("utf8"))
    elif cmd == 'GWD':
        gwd()
    elif cmd == 'CWD':
        cwd(body.decode("utf8"))
    elif cmd == 'LST':
        lst()
    elif cmd == 'UPL':
        filename = body[:255]
        file = body[255:]
        upl(filename, file)
        pass
    elif cmd == 'DNL':
        dnl(body.decode("utf8"))
    elif cmd == 'RMF':
        rmf(remove_padding(body).decode("utf8"))

def main():
    generate_rsa_keys()
    read_users()

    while protocol_state.state == states['WAITING']:
        _, msg = netif.receive_msg(blocking=True)
        auth_status, session_key, addr, username = auth_client(msg)
        print(f"Successful login from address {addr}" if auth_status else "Login rejected")
        if auth_status:
            protocol_state.state = states['ACTIVE']
            protocol_state.session_key = session_key
            protocol_state.req_sqn = -1
            protocol_state.resp_sqn = -1
            protocol_state.addr = addr
            protocol_state.username = username
            protocol_state.working_dir = os.path.join(".", username)
            send_session_accept(addr)

    while protocol_state.state == states['ACTIVE']:
        _, msg = netif.receive_msg(blocking=True)
        process_request(msg)


if __name__ == '__main__':
    main()
