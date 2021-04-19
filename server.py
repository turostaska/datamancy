from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from utils import *
import os.path
from Crypto.PublicKey import RSA


private_key_path = './private-key'


key_pair = None

netif = init_network(server_addr)

def auth_client(ciphertext):
    cipher = PKCS1_OAEP.new(key_pair)
    data = cipher.decrypt(ciphertext)

    type = data[:1]
    if type != types['session_init']:
        print("Invalid message in this state! Awaiting session_init!")
        return

    len = data[1:2]
    if int.from_bytes(len, "big") != 98:
        print("Invalid message length")
        return

    username_padded = data[2:34]
    password_padded = data[34:66]
    session_key_padded = data[66:98]

    username = remove_padding(username_padded)
    password = remove_padding(password_padded)
    session_key = remove_padding(session_key_padded)

    print(username.decode('utf8'))
    print(password.decode('utf8'))
    print(session_key)

    hash = SHA256.new()
    hash.update(password)
    password_hashed = hash.digest()
    print(users[username.decode('utf8')] == password_hashed)

    # header = types['session_init'] + bytes([98])
    # body = pad_to_length(username, 32) + pad_to_length(password, 32)
    #
    # key = RSA.generate(2048)
    #
    # ciphertext = cipher.encrypt(header + body)
    #
    # with open(in_dir + '/' + msgs[self.last_read + 1], 'rb') as f:
    #     msg = f.read()
    pass


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


users = {}

def read_users():
    with open(users_path, 'rb') as f:
        while True:
            username = f.readline()
            password = f.read(33)
            if not username:
                break
            users[(username.decode('utf8')).replace('\n', '')] = password[0:32]


def main():
    generate_rsa_keys()
    read_users()
    status, msg = netif.receive_msg(blocking=True)
    auth_client(msg)


if __name__ == '__main__':
    main()

