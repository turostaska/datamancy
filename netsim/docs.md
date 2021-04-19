Purpose
-------

The purpose of this network simulation package is to provide a simplified network interface abstraction for Python programs implementing cryptographic protocols and thus to help focusing on the crypto stuff instead of worrying about complicated networking issues.


The network interface abstraction
---------------------------------

Programs can instantiate the network_interface class (provided in the netinterface.py module) to create and use a network interface for communications. The network_interface class provides message sending and receiving abstractions via two functions: send_msg() and receive_msg().

The function send_msg(dst, msg) sends out message msg to destination dst, where msg must be a byte string and dst must be a string of valid destination addresses.

Network addresses are capital letters A, B, C, ... Z. Destination dst may contain a single address (e.g., 'A', 'B', ...) or multiple addresses (e.g., 'ABC' means sending the message to A, B, and C). The special broadcast address is +, so dst = '+' will result in sending the message to all addresses.

The function receive_msg(blocking) returns a status flag (Boolean) and a received message (byte string). It can be called in blocking or in non-blocking mode. Blocking mode (calling with blocking=True) means that the function will return only when a new message is available, and in this case, status=True and the received message will be returned. Non-blocking mode (calling with blocking=False) means that the function returns immediately, and if a message was available then status=True and the message will be returned, otherwise status=False and an empty byte string will be returned.

An example for calling receive_msg() in blocking mode is the following:

from netinterface import network_interface
netif = network_interface(NET_PATH, OWN_ADDR)		# create network interface netif
status, msg = netif.receive_msg(blocking=True)		# when returns, status is True and msg contains a message 
print(msg)

An example for calling receive_msg() in non-blocking mode is the following:
 
from netinterface import network_interface
netif = network_interface(NET_PATH, OWN_ADDR)		# create network interface netif
status, msg = netif.receive_msg(blocking=False)    
if status: print(msg)								# if status is True, then a message was returned in msg, and we can print it
else: ...											# otherwise do something else, e.g., wait and try again

Creating a new network interface is done with the constructor of the network_interface class. The constructor takes two input parameters:
- a path where the messages sent to the various addresses are saved in files (e.g., './' or 'C:/network/')
- the address of the new interface being created (e.g., 'A', 'B', ... or 'Z').


The newtork module
------------------

The network is simulated by running the network.py program. This will copy files representing messages from the outgoing folder of the source to the incoming folders of the destinations. The network.py program should be started before any other program relying on the network_interface abstraction described above.

The network.py program is a command line application that can recieve the following parameters as inputs:
- a path where the messages sent to the various addresses are saved in files (e.g., './' or 'C:/network/'); this is provided with command line option -p or --path
- a string containing the valid addresses (e.g., 'ABCDE'); this is provided with command line option -a or --addrspace

If the path is not given as input, it will take deafult value './'. If the address space is not given as input, it will take default value 'ABC'.

The network.py program can also take an optional command line option -c or --clean. When calling with this option, it will delete all previous messages from the incoming and outgoing folders belonging to the network addresses on the given network path.

Examples:

python3 network.py
	running the network simulation with default path './' and default address space 'ABC' (i.e., addresses A, B, and C);
	no clean-up, so messages from a previous run remain in the folders of path './'
	
python3 network.py -p './network/' -a 'ABCDE'
	running the network simulation such that it looks for files representing messages on path './network/'
	and allowing five addresses to be used A, B, C, D, and E;
	no clean-up, so messages from a previous run remain in the folders of path './network/'
	
python3 network.py -p './network/' -a 'ABCDE' --clean
	same as above but cleaning-up all folders on path './network/'
	
Note: Programs using the network_interface class should provide the same network path to the constructor of network_interface as the network path used to start the network simulation program network.py. Also, programs should create network interfaces with addresses that are contained in the address space provided as input to the network simulation program network.py.


More examples
-------------

An example sender and an example receiver applications are provided too (sender.py and receiver.py). Here's how to use them:

python3 network.py -p './network/' -a 'ABCDE' --clean
python3 sender.py -p './network/' -a A
python3 receiver.py -p './network/' -a B

Now, A can send messages to B (given that network.py is running)...
