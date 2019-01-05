/**
* Author: Brandon Jacobs
* Date: 05 OCT 15
* Version: 1.0
**/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in_systm.h> 
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <net/if.h>

#include <netdb.h>


#define	DIVERT_PORT	2000
#define BUFFER_SIZE	65535


static unsigned char ipPacket[BUFFER_SIZE];	/* network packet buffer, from recvfrom(2) */
static struct sockaddr_in *hostIP[8];		/* maximum 8 network interfaces - arbitrary */
static int hostIPCount = 0;
static int divertFd = -1;
static char progName[32];			/* argv[0] */
static int verbose = 0;				/* Verbose mode - informational messages (-v option) */

/*
 * Program implements two security policies - name of program invoked determines
 * which policy is implemented. block_allICMP blocks all ICMP requests that have
 * a source or destination address other than the local host. block_inICMP blocks
 * any ICMP requests that originate from a different host - this security policy
 * allows outbound ping requests from this host and replies from other hosts in
 * response to outbound ping requests.
 *
 * packetFilter()  - implements security policy block_allICMP
 * packetFilter1() - implements security policy block_inICMP
 */

static int (*secPolicy)(struct ip *ipHeader, int protocol, struct in_addr *srcAddr, struct in_addr *dstAddr);

/* Routines */
void signalHandler(int sig);
void getHostAddresses();
int createDivertSocket (uint16_t port);
void processPackets(int fd);
int packetFilter(struct ip *ipHeader, int protocol, struct in_addr *srcAddr, struct in_addr *dstAddr);
int packetFilter1(struct ip *ipHeader, int protocol, struct in_addr *srcAddr, struct in_addr *dstAddr);
void reinjectPacket(int fd, int recvLen, struct sockaddr *saddr, socklen_t saddrLen);

/*
 * block_allICMP - block all ICMP packets with remote host source or destination address
 * block_inICMP  - block incoming ICMP ECHO packets and outgoing ICMP ECHOREPLY packets
 *
 * This program handles both security policies - name of program invoked determines which
 * security policy is in effect. Compile the file block_allICMP.c and then do the following:
 *
 * ln -s block_allICMP block_inICMP
 *
 * Invoke block_allICMP or block_inICMP to see how different security policies behave
 *
 * Arguments: -v (verbose mode, recommended)
 *            -p port  (specifies the divert port, default is 2000)
 *
 * Note: divert port must match the port specified in the ipfw rule
 *
 * Program depends on ipfw configuration - the following rule should be created for
 * ipfw and it should preceed any rules that would otherwise accept or reject icmp
 * packets before they are diverted by the kernel to this program.
 *
 *	ipfw add 100 divert 2000 icmp from any to any
 *
 */

int main(int argc, char **argv)
{
	struct sigaction sigact;
	uint16_t divertPort;
	char hostName[256];
	int opt;

	/* Assign default divert socket in case one is not specified */
	divertPort = DIVERT_PORT;

	/* Set the program name for verbose mode */
	strcpy(progName, argv[0]);

	/* Set the security policy - dynamic pointer to the policy in effect */
	if(strstr(argv[0], "block_inICMP"))
		secPolicy = &packetFilter1;
	else
		secPolicy = &packetFilter;

	/* Process command line options */
	while((opt = getopt(argc, argv, "vp:")) != -1)
	{
		switch (opt)
		{
			case 'v':
				verbose = 1;
				break;

			/* Note: specified port must match the ipfw firewall divert rule port */
			case 'p':
				divertPort = atoi(optarg);
				break;

			case '?':
			default:
				printf("usage: block_allICMP/block_inICMP [-v] [-p port]\n");
				exit(1);
		}
	}

	/* Obtain the name of the host */
	if(gethostname(hostName, sizeof(hostName) - 1))
	{
		fprintf(stderr, "%s: failed to obtain hostname - %d\n", progName, errno);
		exit(1);
	}
	if(verbose)
		printf("%s: host name is %s\n", progName, hostName);

	/* Signal handler for graceful exit/cleanup */
	sigact.sa_handler = signalHandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, (struct sigaction *) NULL);

	/* Build the host IP address list for use in packet filtering */
	(void) getHostAddresses();

	/* Create and bind the divert socket */
	divertFd = createDivertSocket(divertPort);

	if(verbose)
		printf("%s: divert socket successfully bound, preparing to process packets\n", progName);

	/* Process network packets delivered to the divert socket */
	(void) processPackets(divertFd);
	exit(0);
}


/*
 * signalHandler - graceful handling for program termination.
 */

void signalHandler(int sig)
{
	/* Close the divert socket */
	if(divertFd)
		close(divertFd);

	if(verbose)
		printf("%s: exiting\n", progName);

	exit(0);
}

/*
 * getHostAddresses - obtain the IP address(es) for the host to use later in packet filtering.
 *
 * returns: builds a global structure of AF_INET network address structure pointers
 */

void getHostAddresses()
{
	struct ifaddrs *ifaddrs;

	/* Get the host network interface structures to obtain host IP addresses */
	if(getifaddrs(&ifaddrs) == -1)		/* do not free structures; these are used later */
	{
		fprintf(stderr, "%s: failed to retrieve host network interface structures - %d\n", progName, errno);
		exit(1);
	}

	/*
	 * Store the host network interface IP addresses for use later. Ignore the localhost
	 * IP address since it is not used for network packets between this host and others
	 * on the network. Note that the host may have more than network interface and hence
	 * more than one IP address that needs to be factored into packet analysis for any
	 * diverted packets based on the security policy being implemented.
	 */

	while(ifaddrs != (struct ifaddrs *) 0)
	{
		struct sockaddr_in *saddr_in;
		char ifAddress[INET_ADDRSTRLEN];

		/*
		 * Ignore any interfaces that are not up (IFF_UP) or loopback interfaces (IFF_LOOPBACK) 
		 * as well as any interfaces not in the AF_INET family. Could easily be extended to
		 * support IPV6 networks.
		 */

		if(((ifaddrs->ifa_flags & IFF_UP) == 0) || (ifaddrs->ifa_flags & IFF_LOOPBACK) ||
		    (ifaddrs->ifa_addr->sa_family != AF_INET))
		{
			/* Bump to the next interface structure */
			ifaddrs = ifaddrs->ifa_next;
			continue;
		}

		/* Interface is up, is not a loopback interface, and is in the AF_INET family */

		if(verbose)
			printf("%s: interface %s, length %d, family %d\n", progName,
				ifaddrs->ifa_name, ifaddrs->ifa_addr->sa_len, ifaddrs->ifa_addr->sa_family);

		/* ifa_addr points to a sockaddr_in structure for AF_INET */

		saddr_in = (struct sockaddr_in *) ifaddrs->ifa_addr;
		inet_ntop(AF_INET, (void *) &saddr_in->sin_addr, ifAddress, INET_ADDRSTRLEN);

		if(verbose)
			printf("%s: interface/address: %s/%s\n", progName, ifaddrs->ifa_name, ifAddress);

		/* Store a pointer to the interface structure */
		hostIP[++hostIPCount] = (struct sockaddr_in *) ifaddrs->ifa_addr;

		/* Move to the next interface structure in the list */
		ifaddrs = ifaddrs->ifa_next;
	}
}


/*
 * createDivertSocket - create the divert socket and bind it on the specified port.
 *
 * argument: port on which to bind the divert socket
 * returns:  file descriptor for the divert socket
 */

int createDivertSocket (uint16_t port)
{
	int fd, sockOpt, sockOptLen;
	struct sockaddr_in divertSocket;

	if(verbose)
		printf("%s: using %d for divert port\n", progName, port);

	/* Create a divert socket */
	fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);

	if(fd == -1)
	{
		fprintf(stderr, "%s: failed to create divert socket - %d\n", progName, errno);
		exit(1);
	}

	/* Set socket option to allow broadcast packets on the divert socket (for reinjection) */
	sockOpt = 1;
	sockOptLen = sizeof(sockOpt);

	if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &sockOpt, sockOptLen) == -1)
		fprintf(stderr, "%s: failed to set SO_BROADCAST on divert socket - %d\n", progName, errno);

	/*
	 * It is possible due to TIME_WAIT and other network conditions that the port used by
	 * this program for packet diversion may remain bound even though the process that did
	 * the bind(2) has terminated. This will result in the bind(2) below failing even though
	 * our program is no longer able to receive diverted packets. Use the reuseport socket
	 * option to allow the program to successfully bind to the same port.
	 *
	 * Note: option may not be supported on all versions of FreeBSD
	 */

	if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &sockOpt, sockOptLen) == -1)
		fprintf(stderr, "%s: failed to set SO_REUSEPORT on divert socket - %d\n", progName, errno);

	/* Bind the divert socket to the divert port - address for bind is not used */
	memset(&divertSocket, 0, sizeof(divertSocket));
	divertSocket.sin_family = AF_INET;
	divertSocket.sin_port = htons(port);
	divertSocket.sin_addr.s_addr = 0;

	if(bind(fd, (struct sockaddr *) &divertSocket, sizeof(struct sockaddr_in)))
	{
		fprintf(stderr, "%s: failed to bind the divert socket - %d\n", progName, errno);
		exit(1);
	}

	return(fd);
}


/*
 * processPackets - reads the divert socket and filters the packets received. All ICMP traffic is
 * rejected/discarded while all other packets associated with any protocol other than ICMP are
 * passed on by reinjecting into the divert socket to return to the kernel.
 */

void processPackets(int fd)
{
	struct sockaddr saddr;
	socklen_t saddrLen;
	int packetCount;

	/* Read packets from the divert socket continuously */
	packetCount = 1;

	while(1)
	{
		struct ip *ipHeader;
		struct in_addr *srcAddr, *dstAddr;
		struct sockaddr_in *sockAddr;
		int recvLen, protocol;
		char ipSource[INET_ADDRSTRLEN], ipDestination[INET_ADDRSTRLEN];

		/* Prepare for the recvfrom() call to the divert socket */
		saddrLen = sizeof(struct sockaddr);

		/* Read the next packet from the network */
		recvLen = recvfrom(fd, ipPacket, BUFFER_SIZE, 0, &saddr, &saddrLen);

		if(verbose)
		{
			printf("%s: ********** Processing packet #%d **********\n", progName, packetCount++);
			printf("%s: network packet received from kernel, length %d\n", progName, recvLen);
		}

		if(recvLen == 1)
			continue;

		/* Determine the ipfw rule # that caused diversion of the packet */
		sockAddr = (struct sockaddr_in *) &saddr;

		if(verbose)
		{
			printf("%s: packet diverted by ipfw rule - %d\n", progName, sockAddr->sin_port);
			
			if(sockAddr->sin_addr.s_addr == INADDR_ANY)
				printf("%s: packet destination is INADDR_ANY\n", progName);
		}

		/* Extract the protocol ID from the IP header */
		ipHeader = (struct ip *) ipPacket;

		protocol = ipHeader->ip_p;
		/* Source and destination addresses for the packet */

		srcAddr = &ipHeader->ip_src;
		dstAddr = &ipHeader->ip_dst;

		if(verbose)
		{
			/* Convert the source and destination IP addresses to strings */

			strcpy(ipSource,     inet_ntoa(ipHeader->ip_src));
			strcpy(ipDestination,inet_ntoa(ipHeader->ip_dst));

			printf("%s: protocol %d, src %s, dst %s\n", progName, protocol, ipSource, ipDestination);
		}

		/*
		 * Invoke the packet filter routine - if the filter returns 0, then reject the
		 * packet by taking no further action. If the filter returns 1, then the packet
		 * is reinjected into the network stack.
		 */

		if(secPolicy(ipHeader, protocol, srcAddr, dstAddr))
			reinjectPacket(fd, recvLen, &saddr, saddrLen);
	}
}


/*
 * packetFilter
 *
 * This routines implements the security policy for this program. Based on the defined
 * rules for packet accept/reject, the routine returns a value indicating whether or not
 * the packet will be processed normally or rejected.
 *
 * Security Rule: reject ICMP (protocol ID = 1) packets to this host from other hosts
 *
 */

int packetFilter(struct ip *ipHeader, int protocol, struct in_addr *srcAddr, struct in_addr *dstAddr)
{
	int host, sourceOK, destOK;
	in_addr_t loopback;

	/* Convert the loopback interface address to in_addr_t for comparison */
	loopback = inet_addr("127.0.0.1");

	/* Determine if the protocol is ICMP */
	if(protocol == IPPROTO_ICMP)
	{
		struct icmp *icmp;

		if(verbose)
			printf("%s: packet protocol is ICMP\n", progName);

		/* Set pointer to ICMP payload in the IP packet - follows the IP header */
		icmp = (struct icmp *) ((char *) ipHeader + sizeof(struct ip));

		if(verbose)
		{
			if(icmp->icmp_type == ICMP_ECHO)
				printf("%s: ICMP packet type - ICMP_ECHO\n",progName);
			else if(icmp->icmp_type == ICMP_ECHOREPLY)
				printf("%s: ICMP packet type - ICMP_ECHOREPLY\n", progName);
			else
				printf("%s: ICMP packet type - %d\n", progName, icmp->icmp_type);
		}

		/*
	 	 * Reject ICMP packets that have as destination IP this host and a source IP other than
		 * this host. Handle special cases where the source and/or destination are the loopback
		 * interface.
		 */
		
		if(srcAddr->s_addr == loopback)
			sourceOK = 1;
		else
		{
				for(host=1, sourceOK=0; host <= hostIPCount; host++)
				{
					struct sockaddr_in *saddr;

					saddr = hostIP[host];

					/* Compare host IP address(es) to the source address in packet */
					if(saddr->sin_addr.s_addr == srcAddr->s_addr)
						sourceOK = 1;	/* packet originated from an interface on this host */
				}
		}

		if(dstAddr->s_addr == loopback)
			destOK = 1;
		else
		{
				for(host=1, destOK=0; host <= hostIPCount; host++)
				{
					struct sockaddr_in *saddr;

					saddr = hostIP[host];

					/* Compare host IP address(es) to the destination address in packet */
					if(saddr->sin_addr.s_addr == dstAddr->s_addr)
						destOK = 1;	/* packet destined to an interface on this host */
				}
		}
	}
	else
	{
		/* Protocol is other than ICMP - allow packet */
		if(verbose)
			printf("%s: non-ICMP packet, allow/reinject\n", progName);

		return(1);
	}

	/* If either source or destination are from/to different host, reject packet */
	if(!sourceOK || !destOK)
	{
		if(!sourceOK && verbose)
			printf("%s: packet is rejected, source differs from host\n",progName);

		if(!destOK && verbose)
			printf("%s: packet is rejected, destination differs from host\n", progName);
			
		return(0);
	}

	if(srcAddr->s_addr == loopback)
		srcAddr->s_addr = hostIP[1]->sin_addr.s_addr;
	
	/* Packet is OK - reinject into network for delivery as intended */
	if(verbose)
		printf("%s: packet is OK, reinject into network\n", progName);

	return(1);
}


/*
 * packetFilter1
 *
 * This routines implements the security policy for this program. Based on the defined
 * rules for packet accept/reject, the routine returns a value indicating whether or not
 * the packet will be processed normally or rejected.
 *
 * Security Rule: reject ICMP (protocol ID = 1) packets to this host that originate from
 * other hosts. Allow outbound ICMP_ECHO requests from this host to other hosts and allow
 * ICMP_ECHOREPLY responses from other hosts. Inbound ICMP_ECHO requests that originate
 * from other hosts are rejected/blocked.
 *
 */

int packetFilter1(struct ip *ipHeader, int protocol, struct in_addr *srcAddr, struct in_addr *dstAddr)
{
	int host, sourceOK, destOK;

	/* Determine if the protocol is ICMP */
	if(protocol == IPPROTO_ICMP)
	{
		struct icmp *icmp;
		in_addr_t loopback;

		if(verbose)
			printf("%s: packet protocol is ICMP\n", progName);

		/* Convert the loopback interface address to in_addr_t for comparison */
		loopback = inet_addr("127.0.0.1");

		/* Set pointer to ICMP payload in the IP packet - follows the IP header */
		icmp = (struct icmp *) ((char *) ipHeader + sizeof(struct ip));

		if(verbose)
		{
			if(icmp->icmp_type == ICMP_ECHO)
				printf("%s: ICMP packet type - ICMP_ECHO\n",progName);
			else if(icmp->icmp_type == ICMP_ECHOREPLY)
				printf("%s: ICMP packet type - ICMP_ECHOREPLY\n", progName);
			else
				printf("%s: ICMP packet type - %d\n", progName, icmp->icmp_type);
		}

		/*
		 * Reject any incoming ICMP packets that are not of type ICMP_ECHOREPLY. Allow
		 * incoming packets that are of type ICMP_ECHOREPLY and allow outbound ICMP packets
		 * of type ICMP_ECHO (this is the echo request). Do not permit outbound packets
		 * of type ICMP_ECHOREPLY from this host (this is the echo repsonse).
		 */
		
		if(icmp->icmp_type == ICMP_ECHO)
		{
			/* Make sure the source address is one from this host - no incoming ECHO requests */
			if(srcAddr->s_addr == loopback)
				sourceOK = 1;
			else
			{
					for(host=1, sourceOK=0; host <= hostIPCount; host++)
					{
						struct sockaddr_in *saddr;
	
						saddr = hostIP[host];
	
						/* Compare host IP address(es) to the source address in packet */
						if(saddr->sin_addr.s_addr == srcAddr->s_addr)
							sourceOK = 1;	/* packet originated from an interface on this host */
					}
			}

			/* Destination address is OK - wildcard */
			destOK = 1;
		}
		else if(icmp->icmp_type == ICMP_ECHOREPLY)
		{
			/* Make sure the destination address is this host - no outgoing ECHOREPLY packets */
			if(dstAddr->s_addr == loopback)
				destOK = 1;
			else
			{
					for(host=1, destOK=0; host <= hostIPCount; host++)
					{
						struct sockaddr_in *saddr;

						saddr = hostIP[host];

						/* Compare host IP address(es) to the destination address in packet */
						if(saddr->sin_addr.s_addr == dstAddr->s_addr)
							destOK = 1;	/* packet destined to an interface on this host */
					}
			}

			/* Source address is OK - wildcard */
			sourceOK = 1;
		}

	}
	else
	{
		/* Protocol is other than ICMP - allow packet */
		if(verbose)
			printf("%s: non-ICMP packet, allow/reinject\n", progName);

		return(1);
	}

	/* If either source or destination packet check failed, reject the packet */
	if(!sourceOK || !destOK)
	{
		if(!sourceOK && verbose)
			printf("%s: packet is rejected, ECHO request from remote system\n",progName);

		if(!destOK && verbose)
			printf("%s: packet is rejected, ECHOREPLY from local system\n", progName);
			
		return(0);
	}

	/* Packet is OK - reinject into network for delivery as intended */
	if(verbose)
		printf("%s: packet is OK, reinject into network\n", progName);

	return(1);
}


/*
 * reinjectPacket - send the packet back to the kernel stack to be forwarded to original destination.
 */

void reinjectPacket(int fd, int recvLen, struct sockaddr *saddr, socklen_t saddrLen)
{
	int sendLen;

	/* Reinject packet into the network stack */
	if(verbose)
		printf("%s: reinjecting packet for length %d\n", progName, recvLen);

	sendLen = sendto(fd, ipPacket, recvLen, 0, saddr, saddrLen);

	if(sendLen == -1)
		fprintf(stderr, "%s: error on packet reinject sendto() - %d\n", progName, errno);
}


