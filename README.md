# Datamancy

A secure file transfer protocol

Protect your files from untrue policemen

# Setup

1. Change the value of the `master_password` variable to the desired server master password in`generate_private_key.py:8`
2. Run `generate_private_key.py`
3. Enter the desired username-password pairs in the `users` dictionary in  `generate_passwords.py:4`
4. Run `generate_passwords.py`
5. Launch `netsim` with the command `python network.py -p "./network/" -a "AB" --clean`
6. Launch the server with `server.py` and enter the master password
7. Launch the client with `client.py` and enter your credentials
8. Beware of untrue policemen!