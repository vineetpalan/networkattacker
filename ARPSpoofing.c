#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
//#include <bits/ioctls.h>
#include <net/if.h>
#include <netinet/if_ether.h>
//#include <net/ethernet.h>
//#include <netinet/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>


//Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

//Define some constants
#define ETH_HDRLEN 14
#define IP4_HDRLEN 20
#define ARP_HDRLEN 28
#define ARPOP_REPLY 2

int main(int argc, char *argv[])
{
	char *interface, *target ;
	int i, frame_length, sd, bytes;
	arp_hdr arphdr;
	uint8_t src_ip[4], src_mac[6], dst_mac[6], ether_frame[IP_MAXPACKET];
	struct sockaddr_in ipv4;
	struct sockaddr_in device;
	struct ifreq ifr;

	if (argc != 3 ){
		printf("Usage: %s interface target\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	//Interface to send packet through

	interface = argv[1];
	//IP address of the target machine to be spoofed
	target = argv[2];

	//submit request for a socket descripter to look up interface
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror ("socket() failed to get socket descripter for using ioctl()");
		exit (EXIT_FAILURE);
	}

	//use ioctl() to look up interface name and get its IPv4 address
	memset (&ifr, 0, sizeof(ifr));
	snprintf (ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
	if(ioctl (sd, SIOCGIFADDR, &ifr) < 0){
		perror("ioctl() failed to get source IP address");
		return (EXIT_FAILURE);	
	}

	//use ioctl() to look up interface name and get its MAC address
	memset (&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
	if(ioctl (sd, SIOCGIFADDR, &ifr) < 0){
		perror("ioctl() failed to get source MAC address");
		return (EXIT_FAILURE);
	}
	close(sd);

	//copy source MAC address.
	memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6*sizeof(uint8_t));

	//find interface index from interface name and store index in 
	//struct sockaddr_ll device, which will be used as an argument of sendto().
	if((device.sll_ifindex = if_nametoindex(interface))= 0){
		perror("if_nametoindex() failed to obtain interface index");
		exit(EXIT_FAILURE);
	}

	//Set destination MAC address: broadcast address
	memset (dst_mac, 0xff, 6*sizeof(uint8_t));

	//Set source IP: target address
	if(inet_pton(AF_INET, target, &(ipv4.sin_addr)) ==0){
		perror("inet_aton() failed to convert address");
		exit(EXIT_FAILURE);
	}

}