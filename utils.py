from netsim.netinterface import network_interface

types = {
    'session_init': b'\x00',
    'session_accept': b'\x01',
    'session_close': b'\x02',
    'request': b'\x00',
    'response': b'\x01',
}

server_addr = 'A'
network_path = "./netsim/network/"
public_key_path = './public_key'
users_path = './users'

def pad_to_length(to_pad, length):
    assert len(to_pad) <= length

    for i in range(length - len(to_pad)):
        to_pad = to_pad + b'\x00'

    return to_pad


def remove_padding(padded):
    while padded[-1:] == b'\x00':
        padded = padded[0:-1]

    return padded



def init_network(own_addr):
    return network_interface(network_path, own_addr)


# source: https://stackoverflow.com/questions/3812849/how-to-check-whether-a-directory-is-a-sub-directory-of-another-directory/37095733#37095733
def path_is_parent(parent_path, child_path):
    parent_path = os.path.abspath(parent_path)
    child_path = os.path.abspath(child_path)

    return os.path.commonpath([parent_path]) == os.path.commonpath([parent_path, child_path])