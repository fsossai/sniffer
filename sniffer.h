#pragma once

#include "packets.h"

#define BUFFER_SIZE 4096
#define ARG_ERROR "Syntax error\n"
#define MAX_FILTERS 16
#define ARG_MAX_LENGTH 128
#define DIVIDE "----------------------------------------------------\n"

struct filter {
	int ulen;
	int llen;
	char *ulevel_name;
	char *llevel_name;
};

int getmacaddr(unsigned char *mac);
void showf(struct eth_frame *eth, char *outp);
int set_filters(char *llevel);
int sniff();
void process_eth(struct eth_frame *eth, char *outp);
void process_ip(struct ip_datagram *ip, char *outp);
void process_tcp(struct tcp_segment *tcp, char *outp);
void process_udp(struct udp_segment *udp, char *outp);
void free_all();
void print_usage();

