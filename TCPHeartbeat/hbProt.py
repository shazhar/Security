  #!/usr/bin/python

##############################################################################################################################################################################################
# Author: Shahira A. Azhar
# Date: February 09, 2020
##############################################################################################################################################################################################


# ################################################ Imports #####################################################

# System
import sys

# Parser for configuration file
from configparser import ConfigParser

# Parser for command line arguments
import argparse

# Error handling
import errno

# Socket object for TCP connections
from socket import *

# Multithreading support
import threading

# Sleep
from time import sleep

# ########################################## Command-line Options #############################################
# Parse the input arguments and create the args array
parser = argparse.ArgumentParser()
parser.add_argument("--server", action="store_true", default=False, help="Run in server mode")
parser.add_argument("--client", action="store_true", default=False, help="Run in client mode")
parser.add_argument("--terminate", type=int, default=0, help="Terminate connection after specified number of packets sent. Value must be greater than 0")
args = parser.parse_args()

# ########################################## Threaded Functions #############################################

# Data thread
def dataProc(sockobj, dataLim, dataInt, dataEvent, hbEvent):
	global terminate
	global threads
	while not terminate:
		# Wait for activation
		dataEvent.wait()
		# Heartbeat thread is dead, data thread needs to die too
		if not threads[1].is_alive:
			break
		if args.server:
			dataHelper(sockobj[1], dataLim, dataInt)

		elif args.client:
			# Client has to send first message as server starts by just listening
			print("Sending: MSG_DATA")
			sockobj[0].send(b'MSG_DATA')
			dataHelper(sockobj[0], dataLim, dataInt)
		try:
			# Deactivate data thread
			dataEvent.clear()
		except:
			print("WARNING: Exception caught when clearing dataEvent")
		try:
			# Activate heartbeat thread
			hbEvent.set()
		except:
			print("WARNING: Exception caught when setting hbEvent")

# Heartbeat thread
def hbProc(sockobj, hbLim, hbInt, hbEvent, dataEvent):
	global terminate
	global threads
	while not terminate:
		# Activate data thread first
		dataEvent.set()
		# Wait for activation
		hbEvent.wait()
		# Data thread is dead, heartbeat thread needs to die too
		if not threads[0].is_alive:
			break
		if args.server:
			hbHelper(sockobj[1], hbLim, hbInt)
		elif args.client:
			hbHelper(sockobj[0], hbLim, hbInt)
		try:
			# Deactivate heartbeat thread
			hbEvent.clear()
		except:
			print("WARNING: Exception caught when clearing hbEvent")
	# Return functionality to data thread
	dataEvent.set()
			
# ########################################## Helper Functions #############################################

# Helper function for dataProc
def dataHelper(connectorObj, dataLim, dataInt):
	data = ""
	count = 0
	global terminate

	# Forced termination is set
	if args.terminate > 0:
		killCount = args.terminate
	
	while not terminate:

		sleep(dataInt)

		# Kill connection after args.terminate have been sent
		if args.terminate > 0:
			killCount -= 1
			if killCount < 0:
				terminator(connectorObj)
				break

		# Data sending retry limit has been reached, time to enter heartbeat mode
		if count == dataLim:
			print("NOTICE: Reached the data limit!")
			break

		# Try to recieve data from the peer within dataInt seconds
		connectorObj.settimeout(dataInt)
		try:
			data = connectorObj.recv(1024)
		except:
			print("WARNING: Exception caught in data timeout")
			data = ""
		# Reset socket to blocking mode from timeout mode
		connectorObj.settimeout(None)

		# No data was recieved, try again
		if not data: 
			print("NOTICE: Resending data attempt ", count)
			try:
				connectorObj.send(b'MSG_DATA')
			except:
				print("WARNING: Exception caught in data resending")
			# Increment data sending retry count and re-enter loop from beginning
			count = count+1
			continue

		# Request to terminate was received, time to kill yourself
		elif (b'MSG_TERMINATE' in data ):
			if args.client:
				print('NOTICE: Received Terminate from Server:', data)
			elif args.server:
				print('NOTICE: Received Terminate from Client:', data)
			terminate=True
			break

		# Peer is in heartbeat mode, you're too slow 
		elif b'MSG_HEARTBEAT' in data:
			if args.client:
				print('NOTICE: Received Hearbeat from Server:', data)
			elif args.server:
				print('NOTICE: Received Heartbeat from Client:', data)
			try:
				# Echo back their heartbeat to show you're alive!
				connectorObj.send(data)
			except:
				print("WARNING: Exception caught in echoing hearbeat")

		# Peer is sending you data, you send them data too!
		elif (b'MSG_DATA' in data ):
			if args.client:
				print('NOTICE: Received from Server:', data)
			elif args.server:
				print('NOTICE: Received from Client:', data)
			connectorObj.send(b'ACK rcvd MSG_DATA')
		
		# Unexpected case, hasn't occured yet but if it does should not break functionality
		else:
			if args.client:
				print('WARNING: Recieved unknown message from Server: ', data)
			if args.server:
				print('WARNING: Recieved unknown message from Client: ', data)

		# Peer contacted you so reset your data retry count to 0!
		count = 0

# Helper function for hbProc
def hbHelper(connectorObj, hbLim, hbInt):
	global terminate
	global event
	hb = ""
	count = 0

	# Check if peer is still alive with a heartbeat
	try:
		connectorObj.send(b'MSG_HEARTBEAT')
	except:
		print("WARNING: Exception caught in sending hearbeat!")

	while not terminate:

		# Heartbeat retry limit has been reached
		# Peer isn't responding so it's time to kill yourself!
		if count == hbLim:
			terminator(connectorObj)				
			break

		# Listen for heartbeat from peer for at most hbInt seconds
		connectorObj.settimeout(hbInt)
		try:
			hb = connectorObj.recv(1024)
		except:
			hb = ""
		# Reset socket object to normal blocking mode
		connectorObj.settimeout(None)

		# No heartbeat recieved, try again
		if not hb: 
			count = count+1
			print('NOTICE: Sending Heartbeat attempt ', count)
			try:
				connectorObj.send(b'MSG_HEARTBEAT')
			except:
				print("WARNING: Exception caught in sending heartbeat")
			sleep(hbInt)

		# You got a heartbeat! Peer is alive! Go back to sending data
		else:
			if args.server:
				print('NOTICE: Received Heartbeat Echo from Client:', hb)
			elif args.client:
				print('NOTICE: Received Heartbeat Echo from Server:', hb)
			break

# Helper function for terminating connection
def terminator(connectorObj):
	global terminate
	try:
		# Let peer know you're comitting suicide and they should too
		connectorObj.send(b'MSG_TERMINATE')
	except:
		print("WARNING: Exception caught in sending terminate")
	if args.server:
		print('NOTICE: Server shutting down! Requesting Client terminates!')
		# Close the second socket object created for server
		# First socket object will be closed by main thread
		connectorObj.close()
	elif args.client:
		print('NOTICE: Client shutting down! Requesting Server terminates!')
	terminate = True

# Helper function for creating and initializing threads
# threads[0] is data thread
# threads[1] is heartbeat thread
def initThreads(sockobj):
	# Events to handle thread activation
	dataEvent = threading.Event()
	hbEvent = threading.Event()
	# Create the data and heartbeat threads as daemons so that you can keyboard interrupt the process
	threads[0] = threading.Thread(target=dataProc, args=(sockobj, dataLim, dataInt, dataEvent, hbEvent), daemon=True)
	threads[1] = threading.Thread(target=hbProc, args=(sockobj, hbLim, hbInt, hbEvent, dataEvent), daemon=True)
	# Start threads
	threads[0].start()
	threads[1].start()
	# Wait for child threads to return to main thread
	threads[0].join()
	threads[1].join()
	# Close the initially created socket object
	sockobj[0].close()

# Helper function for running as server
def runServer():
	# Create a TCP socket
	sockobj[0] = socket(AF_INET, SOCK_STREAM)
	# Bind socket to specified port and listen for incoming connections
	sockobj[0].bind((ip,port))
	sockobj[0].listen()
	# Accept a connection from the Client
	# Note that Server stalls here until a connection is made
	# Keyboard interrupt is required to exit if no connection is made
	# Could've set a timeout but whatever, not important for this assignment
	sockobj[1], peer = sockobj[0].accept()
	print('NOTICE: Client Connection:', peer)
	initThreads(sockobj)
	# All threads have returned and we are exiting the process
	print("NOTICE: Done running server!")

# Helper function for running as client
def runClient():
	# Create a TCP socket
	sockobj[0] = socket(AF_INET, SOCK_STREAM)
	# Connect to server
	sockobj[0].connect((peer, peerPort))
	initThreads(sockobj)
	# All threads have returned and we are exiting the process
	print("NOTICE: Done running client!")


# ########################################## Main #############################################

# Read configuration parameters from file
config = ConfigParser()
config.read('config.ini')

# Socket object array for dealing with second socket generated by server accepting connections
sockobj = {}
# Thread array for data and heartbeat
threads ={}
# Global flag for program termination
terminate = False

# Running program in server mode
if args.server and not args.client:
	peer 	= ""
	ip 		= config.get('SERVER', 'IP')
	port 	= int(config.get('SERVER', 'Port'))
	dataLim = int(config.get('SERVER', 'DataRetryLimit'))
	dataInt = int(config.get('SERVER', 'DataInterval'))
	hbLim 	= int(config.get('SERVER', 'HeartbeatRetryLimit'))
	hbInt 	= int(config.get('SERVER', 'HeartbeatInterval'))
	print("Running as server")
	runServer()

# Running program in client mode
elif args.client and not args.server:
	peer 	 = config.get('CLIENT', 'PeerIP')
	peerPort = int(config.get('CLIENT', 'PeerPort'))
	dataLim  = int(config.get('CLIENT', 'DataRetryLimit'))
	dataInt  = int(config.get('CLIENT', 'DataInterval'))
	hbLim 	 = int(config.get('CLIENT', 'HeartbeatRetryLimit'))
	hbInt 	 = int(config.get('CLIENT', 'HeartbeatInterval'))
	print("Running as client")
	runClient()
	
# Running program in incorrect mode
else:
	print("You must run as either client or server. Please pick one!")
	exit (1)



