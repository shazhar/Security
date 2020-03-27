<pre>
A simple TCP Client/Server application that uses a "heartbeat" protocol

Requires: 
			Python 3

Setup:
			Populate config.ini with configuration parameters for Client/Server 

Run:
			Must run as either server or client.
			To force termination after specified amount of packets sent use terminate argument

			$ python3 hbProt.py <arguments>


usage: a2.py [-h] [--server] [--client] [--terminate TERMINATE]

optional arguments:
  -h, --help            show this help message and exit
  --server              Run in server mode
  --client              Run in client mode
  --terminate TERMINATE
                        Terminate connection after specified number of packets
                        sent. Value must be greater than 0
</pre>
