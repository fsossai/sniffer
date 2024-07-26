#include "nets.h"
#include "netdata.h"

#define BUFFER_SIZE 4096
#define ARG_ERROR "Errore di sinstassi\n"
#define MAX_FILTERS 16
#define ARG_MAX_LENGTH 128
#define DIVIDE "----------------------------------------------------\n"

int ifindex;
char debug = 0;
char dim = 0;
char printed;
unsigned short flags = 0x00;
struct filter filters[MAX_FILTERS];
int filters_counter;

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

int main(int argc, char *argv[])
{
	int i;
	filters_counter = 0;
	if (argc == 1) {
		print_usage();
		return 0;
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-f")) {
			if (set_filters((i + 1 < argc) ? argv[i + 1] : NULL) <
			    0)
				return -1;
		} else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--all"))
			flags |= F_ALL;
		else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--dim"))
			flags |= F_DIM;
		else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--levels"))
			flags |= F_LEVELS;
		else if (!strcmp(argv[i], "--help")) {
			print_usage();
			free_all();
			return 0;
		}
	}
	sniff();
	free_all();
	return 0;
}

int set_filters(char *llevel)
{
	int i = 0;
	if (!llevel) {
		printf(ARG_ERROR);
		return -1;
	}
	char *ulevel = llevel;
	while (llevel[i]) {
		if (llevel[i] == '.') {
			llevel[i] = '\0';
			ulevel = &llevel[i + 1];
			break;
		}
		i++;
	}
	filters[filters_counter].ulen = strlen(ulevel);
	filters[filters_counter].ulevel_name =
		(char *)malloc(filters[filters_counter].ulen);
	strcpy(filters[filters_counter].ulevel_name, ulevel);

	if (llevel == ulevel)
		filters[filters_counter].llen = filters[filters_counter].ulen;
	else
		filters[filters_counter].llen = strlen(llevel);
	filters[filters_counter].llevel_name =
		(char *)malloc(filters[filters_counter].llen);
	strcpy(filters[filters_counter].llevel_name, llevel);

	printf("Filter all '%s' that carry '%s' data\n",
	       filters[filters_counter].llevel_name,
	       filters[filters_counter].ulevel_name);

	filters_counter++;
	return 0;
}

int sniff()
{
	int s, r, len;
	unsigned long total_data = 0;
	unsigned long packets_received = 0;
	char buffer[BUFFER_SIZE], outp[ARG_MAX_LENGTH];
	struct sockaddr_ll sll;
	struct sockaddr *src_addr = (struct sockaddr *)&sll;
	struct eth_frame *eth = (struct eth_frame *)buffer;
	struct ip_datagram *ip = (struct ip_datagram *)eth->payload;
	struct arp_packet *arp = (struct arp_packet *)eth->payload;
	len = sizeof(struct sockaddr_ll);
	memset(&sll, 0, (sizeof(struct sockaddr_ll)));
	sll.sll_family = AF_PACKET;
	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) {
		perror("sniff");
		return -1;
	}

	while (1) {
		printed = 0;
		outp[0] = '\0';
		r = recvfrom(s, buffer, BUFFER_SIZE, 0, src_addr, &len);
		total_data += r;
		packets_received++;
		if (flags & F_DIM)
			printf("Frame size: %i bytes\n", r);
		process_eth(eth, outp);
		if (flags & F_LEVELS)
			printf(" %s\t (%.4i B)\n", outp, r);
		showf(eth, outp);
		if (printed)
			printf(DIVIDE);
	}
}

void showf(struct eth_frame *eth, char *outp)
{
	char *start, *end, *cur, all = flags & F_ALL;
	int i, j;
	struct ip_datagram *ip = (struct ip_datagram *)eth->payload;
	struct arp_packet *arp = (struct arp_packet *)eth->payload;
	struct icmp_packet *icmp = (struct icmp_packet *)ip->payload;
	struct tcp_segment *tcp = (struct tcp_segment *)ip->payload;
	struct udp_segment *udp = (struct udp_segment *)ip->payload;
	for (i = 0; i < filters_counter || all; i++) {
		start = NULL;
		if (i < filters_counter)
			start = strstr(outp, filters[i].llevel_name);
		if (!start && !all)
			continue;
		if (i < filters_counter)
			end = strstr(outp, filters[i].ulevel_name);
		if (start <= end || all) {
			if (all) {
				for (j = strlen(outp) - 1;
				     (j >= 0) && (outp[j] != '.'); j--)
					;
				cur = &outp[j + 1];
			} else
				cur = filters[i].llevel_name;
			printed = 1;
			if (!strcmp(cur, "eth"))
				print_eth(eth);
			else if (!strcmp(cur, "arp"))
				print_arp(arp);
			else if (!strcmp(cur, "ip"))
				print_ip(ip);
			else if (!strcmp(cur, "icmp"))
				print_icmp(icmp);
			else if (!strcmp(cur, "tcp"))
				print_tcp(tcp, htons(ip->totlen) - 20);
			else if (!strcmp(cur, "udp"))
				print_udp(udp);
		}
	}
}

void process_eth(struct eth_frame *eth, char *outp)
{
	unsigned short current_type;
	current_type = htons(eth->type);
	strcat(outp, "eth");
	switch (current_type) {
	case 0x0800:
		strcat(outp, ".ip");
		process_ip((struct ip_datagram *)eth->payload, outp);
		break;
	case 0x0806:
		strcat(outp, ".arp");
		break;
	default:
		strcat(outp, ".unk2");
		// printf("Ethernet ULP unknown: %i\n",current_type);
		break;
	}
}

void process_ip(struct ip_datagram *ip, char *outp)
{
	void *pl = ip->payload;
	switch (ip->protocol) {
	case 1:
		strcat(outp, ".icmp");
		break;
	case 6:
		strcat(outp, ".tcp");
		break;
	case 17:
		strcat(outp, ".udp");
		break;
	default:
		strcat(outp, ".unk3");
		// printf("IP ULP unknown: %i\n",ip->protocol);
		break;
	}
}

void process_tcp(struct tcp_segment *tcp, char *outp)
{
}

void process_udp(struct udp_segment *udp, char *outp)
{
}

void free_all()
{
	for (int i = 0; i < filters_counter; i++) {
		free(filters[i].ulevel_name);
		free(filters[i].llevel_name);
	}
}

void print_usage()
{
	printf("Usage: sniffer [-adl] [-f <llp_name.ulp_name>]\n\n");
	printf("  -a, --all\tDisplay all headers of incoming packets.\n");
	printf("  -d, --dim\tDisplay dimension of incoming ethernet frames.\n");
	printf("  -l, --levels\tDisplay protocol types contained.\n");
	printf("  -f\t\tFilter headers and display only <llp_name> protocol type that contains an <ulp_name> protocol type.\n");
	printf("\nExample: sniffer -f eth.tcp\n"
	       "         sniffer -f arp\n");
}
