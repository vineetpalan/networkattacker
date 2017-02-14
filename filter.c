#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct{
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t total_length;
	uint16_t id;
	uint16_t flags_fo;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_header_t;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t data_offset; //4 bits
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} tcp_header_t;

/* Internet checksum function (from BSD tahoe) */
unsigned short in_cksum(unsigned short *addr, int len){
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	
	while(nleft > 1){
	sum += *w++;
	nleft -= 2;

	}
	if (nleft == 1){
 	*(unsigned char *) (&answer) = *(unsigned char *) w;
	sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
	
}
/*  TCP checksum function (handles pseudo TCP header) */
	uint16_t tcp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr){
	const uint16_t *buf=buff;
	uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
	uint32_t sum;
	size_t length=len;
	

	//calculate the sum
	sum =0 ;
	while(len > 1){
		sum += *buf++;
		if(sum & 0x80000000)
		sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if(len & 1)
	//Add the pading if the packet length is odd
	sum += *((uint8_t *)buf);
	//Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(IPPROTO_TCP);
	sum += htons(length);
	
	//Add the carries 
	while(sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	//Return the one's complement of sum
	return ((uint16_t)(~sum) );
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb){
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;
	
	ph = nfq_get_msg_packet_hdr(tb);
	if(ph){
		id = ntohl(ph->packet_id);
		printf("hw_protocol = 0x%04x hook=%u id=%u",ntohs(ph->hw_protocol), ph->hook, id);
	}
	hwph = nfq_get_packet_hw(tb);
	if(hwph){
		int i, hlen = ntohs(hwph->hw_addrlen);
		
		printf("hw_src_addr=");
		for(i=0;i<hlen-1; i++)
		printf("%02x:", hwph->hw_addr[i]);
		printf("%02x", hwph->hw_addr[hlen-1]);
	}
	
	mark = nfq_get_nfmark(tb);
	if(mark)
		printf("mark=%u", mark);

	ifi = nfq_get_indev(tb);
	if(ifi)
		printf("indev=%u", ifi);
	ifi = nfq_get_outdev(tb);
	if(ifi)
		printf("outdev=%u", ifi);
	ifi = nfq_get_physindev(tb);
	if(ifi)
		printf("physindev=%u", ifi);
	if(ifi)
		printf("physoutdev=%u", ifi);
	ret = nfq_get_payload(tb, &data);
	if(ret >=0 )
		printf("payload_len=%d", ret);
	fputc('\n', stdout);
	return id;
}

	static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
	{
		unsigned char *pkt_data;
	//	char dotted_addr[INET_ADDRSTRLEN];
		int ip_len;
		int modified = 0;
		int ret;
		u_int32_t id = print_pkt(nfa);
		ip_header_t *iph;
		tcp_header_t *tcph;
		uint32_t target_addr = htonl(0xC0A81E79);
		uint32_t my_addr = htonl(0xC0A81E7D);		

		ret = nfq_get_payload(nfa, &pkt_data);
		if(ret >= 0){
		iph = (ip_header_t*)pkt_data;
		ip_len = (iph->ver_ihl & 0xF) * 4;
		tcph = (tcp_header_t*)(pkt_data + ip_len);
			if(iph->dst_addr == target_addr){
			iph->dst_addr = my_addr;
			modified = 1;
			}
			else if(iph->src_addr == my_addr){
			iph->src_addr = target_addr;
			modified = 1;
			}
		//ip_header_t *iph = (ip_header_t*)pkt_data;
		//inet_ntop(AF_INET, &(iph->dst_addr), dotted_addr, INET_ADDRSTRLEN);
		//printf("%s\n",dotted_addr);
		
		/*if(iph->dst_addr != htonl(0x7f000001)){
			iph->dst_addr = htlon(0x7f000001);
			iph->checksum = 0;
			iph->checksum =in_cksum((unsigned short *)iph, sizeof(ip_header_t));
				return nfq_set_verdict(qh, id, NF_ACCEPT, ret, (const unsigned char*)pkt_data);
		
		}*/
			if(modified){
				iph->checksum = 0;
				iph->checksum = in_cksum((unsigned short *)iph, ip_len);
				tcph->checksum = 0;
				tcph->checksum = tcp_checksum(tcph, ret - ip_len, iph->src_addr, iph->dst_addr);
				return nfq_set_verdict(qh, id, NF_ACCEPT, ret, (const unsigned char*)pkt_data);
			}
		}
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	int main(int argc , char **argv){
		struct nfq_handle *h;
		struct nfq_q_handle *qh;
		struct nfnl_handle *nh;
		int fd;
		int rv;
		char buf[4096] __attribute__ ((aligned));
		
		h = nfq_open();
		if(!h){
			fprintf(stderr, "error during nfq_open()\n");
			exit(1);
		}
		
		if(nfq_unbind_pf(h, AF_INET) < 0){
			fprintf(stderr, "error during nfq_unbind_pf()\n");
			exit(1);
		}
		if(nfq_bind_pf(h, AF_INET < 0)){
			fprintf(stderr, "error during nfq_bind_pf()\n");
			exit(1);
		}
		
		qh = nfq_create_queue(h, 0, &cb, NULL);
		if(!qh){
			fprintf(stderr, "error during nfq_create_queue()\n");
			exit(1);	
		}

		if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
			fprintf(stderr, "can't set packet_copy mode \n");
			exit(1);	
		}
		
		fd = nfq_fd(h);
		while((rv = recv(fd, buf, sizeof(buf),0)) &&rv >=0){
			nfq_handle_packet(h, buf, rv);
		}
		nfq_destroy_queue(qh);

		nfq_close(h);
		exit(0);
}
