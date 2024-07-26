#pragma once

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define HWADDR_LENGTH 6

struct udp_segment {};

struct tcp_segment {
	unsigned short s_port;
	unsigned short d_port;
	unsigned int seq;
	unsigned int ack;
	unsigned char d_offs_res;
	unsigned char flags;
	unsigned short win;
	unsigned short checksum;
	unsigned short urgp;
	unsigned char payload[1];
};

struct icmp_packet {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
	unsigned char payload[1];
};

struct ip_datagram {
	unsigned char ver_ihl;
	unsigned char tos;
	unsigned short totlen;
	unsigned short id;
	unsigned short flags_offs;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int src;
	unsigned int dst;
	unsigned char payload[1];
};

struct arp_packet {
	unsigned short htype;
	unsigned short ptype;
	unsigned char hlen;
	unsigned char plen;
	unsigned short opcode;
	unsigned char hsrc[6];
	unsigned char psrc[4];
	unsigned char hdst[6];
	unsigned char pdst[4];
};

struct eth_frame {
	unsigned char dst[6];
	unsigned char src[6];
	unsigned short type;
	unsigned char payload[1];
};

void printb(const char *head, const char *format, const char *str, int dim)
{
	printf("%s", head);
	for (int i = 0; i < dim; i++) {
		printf(format, str[i], str[i], str[i]);
	}
	printf("\n");
}
