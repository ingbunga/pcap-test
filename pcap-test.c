#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <libnet.h>

#define SIZE_ETHERNET 14

void print_mac(const uint8_t* mac) {
	for (int i = 0; i < ETHER_ADDR_LEN - 1; i++) {
		printf("%02x:", mac[i]);
	}
	printf("%2x", mac[ETHER_ADDR_LEN - 1]);
}

void
pcap_receiver(const struct pcap_pkthdr *header, const u_int8_t *packet)
{
	const struct libnet_ethernet_hdr *ethernet;
	const struct libnet_ipv4_hdr *ip;
	const struct libnet_tcp_hdr *tcp;
	const u_int8_t *payload;

	int size_ip;
	int size_tcp;
	int size_payload;

	ethernet = (struct libnet_ethernet_hdr*)(packet);
	ip = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl * 4;

	if (size_ip < 20 ||
		ip->ip_p != IPPROTO_TCP) return;


	tcp = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = tcp->th_off * 4;

	if (size_tcp < 20) return;

	printf("    Src MAC: ");
	print_mac(ethernet->ether_shost);
	printf("\n    Dst MAC: ");
	print_mac(ethernet->ether_dhost);
	printf("\n");

	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	payload = (u_int8_t *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	{
		printf("    Payload: ");
		int n = size_payload > 20 ? 20 : size_payload;

		if (n <= 0) 
			printf("None");
		for (int i = 0; i < n; i++) 
			printf("0x%02x ", (unsigned int)payload[i]);
		printf("\n\n");
	}

	return;
}


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_int8_t* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		pcap_receiver(header, packet);
		// printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
