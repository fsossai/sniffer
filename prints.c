#include <stdio.h>

#include <arpa/inet.h>
#include <netdb.h>

#include "packets.h"

void print_bytes(const char *head, const char *format, const char *str, int dim)
{
	printf("%s", head);

	for (int i = 0; i < dim; i++) {
		printf(format, str[i], str[i], str[i]);
	}

	printf("\n");
}

void print_eth(struct eth_frame *eth)
{
	int i, max_i = 6;
	unsigned short type = htons(eth->type);
	printf(" ETH FRAME\n");
	printf("Destination address: ");
	for (i = 0; i < max_i; i++)
		printf("%.2x%c", eth->dst[i], (i + 1 < max_i) ? ':' : 0);
	printf("\nSource address: ");
	for (i = 0; i < max_i; i++)
		printf("%.2x%c", eth->src[i], (i + 1 < max_i) ? ':' : 0);
	printf("\nType: 0x%.2x 0x%.2x (", ((unsigned char *)&eth->type)[0],
	       ((unsigned char *)&eth->type)[1]);
	switch (type) {
	case 0x0800:
		printf("ip");
		break;
	case 0x0806:
		printf("arp");
		break;
	default:
		printf("?");
		break;
	}
	printf(")\n");
	printf("\n");
}

void print_ip(struct ip_datagram *ip)
{
	struct protoent *pe = getprotobynumber(ip->protocol);
	printf("Version: IPv%i\n", (ip->ver_ihl & 0xF0) >> 4);
	printf("Header length: %i\n", (ip->ver_ihl & 0x0F) * 4);
	printf("Type of service: %s delay, %s throughput, %s reliability\n",
	       (ip->tos & 0x10) ? "Low" : "Normal",
	       (ip->tos & 0x8) ? "High" : "Normal",
	       (ip->tos & 0x4) ? "High" : "Normal");
	printf("Total length: %i\n", htons(ip->totlen));
	printf("Identification: %i\n", htons(ip->id));
	printf("Flags: %s fragment, %s fragment/s\n",
	       (ip->flags_offs & 0x4000) ? "Dont't" : "May",
	       (ip->flags_offs & 0x2000) ? "More" : "Last");

	printf("Fragment offset: %i\n", ip->flags_offs & 0x1FFF);
	printf("Time to live: %i\n", ip->ttl);
	printf("Protocol: %i (%s)\n", ip->protocol, (pe) ? pe->p_name : "?");
	printf("Header checksum: 0x%.2X 0x%.2X\n", (ip->checksum & 0xFF00) >> 8,
	       ip->checksum & 0x00FF);
	printf("Source address: %i.%i.%i.%i\n", ((unsigned char *)&ip->src)[0],
	       ((unsigned char *)&ip->src)[1], ((unsigned char *)&ip->src)[2],
	       ((unsigned char *)&ip->src)[3]);
	printf("Destination address: %i.%i.%i.%i\n",
	       ((unsigned char *)&ip->dst)[0], ((unsigned char *)&ip->dst)[1],
	       ((unsigned char *)&ip->dst)[2], ((unsigned char *)&ip->dst)[3]);
	printf("\n");
}

void print_arp(struct arp_packet *arp)
{
	int i, max_i;
	unsigned short htype;
	unsigned short opcode = htons(arp->opcode);
	printf(" ARP PACKET\n");
	printf("Hardware type: ");
	switch (htype = htons(arp->htype)) {
	case 1:
		printf("ethernet");
		break;
	default:
		printf("%i", htype);
		break;
	}
	printf("\n");
	printf("Protocol type: %i\n", arp->ptype);
	printf("Hardware address length: %i\n", arp->hlen);
	printf("Protocol address length: %i\n", arp->plen);
	printf("Opcode: %i (", opcode);
	switch (opcode) {
	case 1:
		printf("request");
		break;
	case 2:
		printf("reply");
		break;
	case 3:
		printf("request reverse");
		break;
	case 4:
		printf("reply reverse");
		break;
	case 5:
		printf("DRARP request");
		break;
	case 6:
		printf("DRARP reply");
		break;
	case 7:
		printf("DRARP error");
		break;
	case 8:
		printf("InARP request");
		break;
	case 9:
		printf("InARP reply");
		break;
	case 10:
		printf("ARP NAK");
		break;
	default:
		printf("?");
		break;
	}
	printf(")\n");
	printf("Source hardware address: ");
	max_i = arp->hlen;
	for (i = 0; i < max_i; i++)
		printf("%.2x%c", arp->hsrc[i], (i + 1 < max_i) ? ':' : 0);
	printf("\nSource protocol address: ");
	max_i = arp->plen;
	for (i = 0; i < max_i; i++)
		printf("%i%c", arp->psrc[i], (i + 1 < max_i) ? '.' : 0);
	printf("\nDestination hardware address: ");
	max_i = arp->hlen;
	for (i = 0; i < max_i; i++)
		printf("%.2x%c", arp->hdst[i], (i + 1 < max_i) ? ':' : 0);
	printf("\nDestination protocol address: ");
	max_i = arp->plen;
	for (i = 0; i < max_i; i++)
		printf("%i%c", arp->pdst[i], (i + 1 < max_i) ? '.' : 0);
	printf("\n\n");
}

void print_icmp(struct icmp_packet *icmp)
{
	printf(" ICMP PACKET\n");
	printf("Type: ");
	switch (icmp->type) {
	case 0:
		printf("Echo Reply Message\n");
		break;
	case 3:
		printf("Destination Unreachable\n");
		break;
	case 4:
		printf("Source Quench Message\n");
		break;
	case 5:
		printf("Redirect Message\n");
		break;
	case 8:
		printf("Echo Message\n");
		break;
	case 11:
		printf("Time Exceeded Message\n");
		break;
	case 12:
		printf("Parameter problem message\n");
		break;
	case 13:
		printf("Timestamp Message\n");
		break;
	case 14:
		printf("Timestamp Reply Message\n");
		break;
	case 15:
		printf("Information Request Message\n");
		break;
	case 16:
		printf("Timestamp Reply Message\n");
		break;
	}
	printf("Code: ");
	if (icmp->type == 3) {
		switch (icmp->code) {
		case 0:
			printf("Net unreachable");
			break;
		case 1:
			printf("Host unreachable");
			break;
		case 2:
			printf("Protocol unreachable");
			break;
		case 3:
			printf("Port unreachable");
			break;
		case 4:
			printf("Fragmentation needed and DF set");
			break;
		case 5:
			printf("Source route failed");
			break;
		default:
			printf("?");
			break;
		}
	}
	if (icmp->type == 5) {
		switch (icmp->code) {
		case 0:
			printf("Redirect datagrams for the Network");
			break;
		case 1:
			printf("Redirect datagrams for the Host");
			break;
		case 2:
			printf("Redirect datagrams for the Type of Service and Network");
			break;
		case 3:
			printf("Redirect datagrams for the Hosedirect datagrams for the Host");
			break;
		default:
			printf("?");
			break;
		}
	} else if (icmp->type == 11) {
		switch (icmp->code) {
		case 0:
			printf("Time to live exceeded in transit");
			break;

		case 1:
			printf("fragement reassembly time exceeded");
			break;
		default:
			printf("?");
			break;
		}
	} else if (icmp->type == 12) {
		if (icmp->code == 0)
			printf("pointer (identifier) indicates the error");
	} else
		switch (icmp->type) {
		case 4:
		case 13:
		case 14:
		case 15:
		case 16:
			printf("0");
			break;
		case 0:
		case 8:
			break;
		default:
			printf("?");
			break;
		}
	switch (icmp->type) {
	case 0:
	case 8:
		printf("Identifier: %i\n", htons(icmp->id));
		printf("Sequence Number: %i\n", htons(icmp->seq));
		break;
	default:
		printf("?");
		break;
	}
}

void print_tcp(struct tcp_segment *tcp, int plength)
{
	unsigned char mask = 0x20;
	unsigned char f = tcp->flags;
	unsigned char doffset = (tcp->d_offs_res & 0xF0) >> 4;
	printf(" TCP SEGMENT\n");
	printf("Source port: %i\n", htons(tcp->s_port));
	printf("Destination port: %i\n", htons(tcp->d_port));
	printf("Sequence number: %u\n", htonl(tcp->seq));
	printf("Ack number: %u\n", htonl(tcp->ack));
	printf("Data offset: %i\n", doffset);
	printf("Reserved: 0x%.2X\n",
	       ((tcp->d_offs_res & 0x0F) << 2) | ((tcp->flags & 0xC0) >> 6));
	printf("Flags: 0x%.2X\n", (tcp->flags & 0x3F));
	if (f & (mask >> 0))
		printf(" - Urgent Pointer field significant\n");
	if (f & (mask >> 1))
		printf(" - Acknowledgment field significant\n");
	if (f & (mask >> 2))
		printf(" - Push Function\n");
	if (f & (mask >> 3))
		printf(" - Reset the connection\n");
	if (f & (mask >> 4))
		printf(" - Synchronize sequence numbers\n");
	if (f & (mask >> 5))
		printf(" - No more data from sender\n");
	printf("Window: %i\n", htons(tcp->win));
	printf("Header checksum: 0x%.2X 0x%.2X\n",
	       (tcp->checksum & 0xFF00) >> 8, tcp->checksum & 0x00FF);
	printf("Urgent pointer: %i\n", htonl(tcp->urgp));
	print_bytes("Payload: ", "%c", &((char *)tcp)[4 * doffset], plength);
	printf("\n");
}

void print_udp(struct udp_segment *udp)
{
	printf(" UDP SEGMENT\n");
}
