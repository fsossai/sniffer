#pragma once

#include "packets.h"

void print_bytes(const char *head, const char *format, const char *str, int dim);
void print_eth(struct eth_frame *eth);
void print_ip(struct ip_datagram *ip);
void print_arp(struct arp_packet *arp);
void print_icmp(struct icmp_packet *icmp);
void print_tcp(struct tcp_segment *tcp, int plength);
void print_udp(struct udp_segment *udp);
