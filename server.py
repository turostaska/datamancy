def print_hi(name):
    print(f'Most már az irl beszélgetrsekben is jelen van {name}!')


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
    print_hi('Amy')
