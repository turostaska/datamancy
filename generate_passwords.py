from Crypto.Hash import SHA256
from utils import *

users = {
    "amyglassires": "afraidofuntruecops",
    'faci': 'isomuchdesireflora',
    'rolcsi': ':D',
}

def hash_and_print_users():
    with open(users_path, 'wb') as f:
        for username, password in users.items():
            hash = SHA256.new()
            hash.update(password.encode())
            f.write(username.encode())
            f.write(b'\n')
            f.write(hash.digest())
            f.write(b'\n')


if __name__ == '__main__':
    hash_and_print_users()