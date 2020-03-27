#!/bin/bash
##############################################################################################################################################################################################
# Author: Shahira A. Azhar
# Date: January 27, 2020
##############################################################################################################################################################################################

# Validate input arguments
# Redirect all error logs to STDERR so that user can redirect errors to null if desired when running script
function Validate () {

	# Set maxAttempt to default if no user input
	if [[ -z $maxAttempt ]]; then
		maxAttempt=2
	# Check if maxAttempt is an integer value
	elif ! [[ $maxAttempt =~ ^[0-9]+$ ]]; then
		echo "ERROR: Maximum attempt MUST be an integer value between 1 and 6!" >&2; exit 1
	# Check if 0 < maxAttempt <= 6
	elif [[ $maxAttempt -gt 6 ]]; then
		echo "ERROR: You are allowing too many attempts! This is unsafe! No more than 6!" >&2; exit 1
	elif [[ $maxAttempt -le 0 ]]; then
		echo "ERROR: Come one now, you have to allow at least one login attempt." >&2; exit 1
	fi

	# By default there is no timeout unless user supplies an integer value
	if [[ -n $timeout ]]; then
		if ! [[ $timeout =~ ^[0-9]+$ ]]; then
			echo "ERROR: Timeout MUST be an integer value!" >&2; exit 1
		fi
	fi

	# Set log file to default if no user input
	if [[ -z $logFile ]]; then
		logFile="/var/log/secure"
	fi

	# Set key phrase to default if no user input
	if [[ -z $keyPhrase ]]; then
		keyPhrase="Failed password"
	fi
}

# Block suspicious IP with iptable rule
function blockIP () {

	# You wouldn't have console logs in the field
	# Included only for debugging purposes and to simplify demonstration
	echo "Blocking $ip"
	iptables -A INPUT -s $ip -j DROP

	# If a timeout is specified then unblock IP and remove it from the strike list
	if [ -n "$timeout" ]; then
		echo "Unblock $ip in $timeout minutes"
		# Redirect stdout of at command to null
		# Do not redirect stderr in case OS does not have at installed 
		echo "iptables -D INPUT -s "$ip" -j DROP" | at now + $timeout minute > /dev/null
		# Once an IP is blocked it is unable to gain access to a remote session for another login attempt
		# That means it will not be written to the monitored log again, until timeout
		# So there will be no more strikes until timeout; hence why it is safe to remove from strikeList now
		unset strikeList[$ip]
	fi

}

function Run () {
	# Read line from log using file descriptor
	while read -u ${log} message
	do
		# Check to see if log message is a failed authentication attempt
		if [[ $message == *"$keyPhrase"* ]]; then
			# Find ipv4 address from message using regex and extract it into ip
			# 1-3 decimal digits followed by a dot repeated thrice
			# Followed by one last instance of 1-3 decimal digits
			ip=$(echo $message | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
			# Check if ip was properly extracted
			if [[ $ip =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
				echo $ip

				# IP is already in the strikelist
				if [[ -v strikeList[$ip] ]]; then
					# Increment strike count
					strikeList[$ip]=$(( strikeList[$ip]+1 ))
					# Block IP if max attempts have been reached
					if [ ${strikeList[$ip]} -eq $maxAttempt ]; then
						blockIP
					fi
				else
					# Add IP to strike list
					strikeList[$ip]=1
					if [ $maxAttempt -eq 1 ]; then
						# Only allowed for one attempt which they failed, so they get blocked right away
						blockIP
					fi
				fi
			fi
		fi
	done
}

main () {

	# Validate user input and assign defaults where needed
	Validate

	# Associative array for strike list where key=ip, and value=strike count
	declare -A strikeList

	# Create a file descriptor for reading from log
	# Using file descriptor because it makes reading new data easier as pointer location is tracked
	# Note that killing a process closes open FD's used by the process
	# Not very safe practice but good enough to take advantage of for the scope of this assignment
	exec {log}<${logFile}

	# Run until SIGINT (ctrl-c)
	while :
	do
		Run
	done
}


usage="$(basename "$0") [-h] [-a n] [-t n] [-p str] [-k str]

A simple intrusion prevention system to block suspicious addresses from bruteforcing your accounts

Where:
	-h show this help text
	-a set the maximum login attempt value (default: 2, min: 1, max: 6)
	-t set the timeout (min) value for blocking the IP (default: infinite)
	-p set the path to the log file you wish to monitor (default: /var/log/secure)
	-k set the key phrase that indicates a failed authentication attempt in the user
	   supplied log. Ex. \"authentication failure\" (default: \"Failed password\")
"

while getopts ':ha:t:p:k:' option; do
	case ${option} in
		h) echo "$usage"
		   exit
		   ;;
		a) maxAttempt=$OPTARG
		   ;;
		# Should be hours but for purpose of demonstration treating as minutes
		# By default no timeout
		t) timeout=$OPTARG
		   ;;
		p) logFile=$OPTARG
		   ;;
		k) keyPhrase=$OPTARG
		   ;;
		\?) printf "Illegal option: -%s\n" "$OPTARG" >&2
			echo "$usage" >&2
			exit 1
			;;
	esac
done
shift $((OPTIND -1))

# No need to pass arguments because any user input has already been assigned to a variable
main





