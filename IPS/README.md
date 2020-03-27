IPS.sh [-h] [-a n] [-t n] [-p str] [-k str]

A simple intrusion prevention system to block suspicious addresses from bruteforcing your accounts

Where:
	-h show this help text
	-a set the maximum login attempt value (default: 2, min: 1, max: 6)
	-t set the timeout (min) value for blocking the IP (default: infinite)
	-p set the path to the log file you wish to monitor (default: /var/log/secure)
	-k set the key phrase that indicates a failed authentication attempt in the user
	   supplied log. Ex. "authentication failure" (default: "Failed password")

Requirements:
	- at command installed
	- root permission to run script
	- absolute path to non-default log file 
	- exact spelling and format of key phrase for authentication failure in non-default log file