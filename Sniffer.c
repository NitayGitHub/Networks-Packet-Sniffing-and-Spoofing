#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN	6

typedef unsigned char u_char;
typedef unsigned short u_short;

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;

	if (ntohs(eth->ether_type) == 0x0800)
	{ // 0x0800 is IP type
		struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

		printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
		printf("         To: %s\n", inet_ntoa(ip->iph_destip));

		/* determine protocol */
		switch (ip->iph_protocol)
		{
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			return;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		default:
			printf("   Protocol: others\n");
			return;
		}
		puts("");
	}
}

// Packet Sniffing using the pcap API
int main(int argc, char *argv[])
{
	char *dev = argv[1]; /* Device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp portrange 9998-9999"; /* The filter expression */
	bpf_u_int32 net;							   /* The IP of our sniffing device */

	printf("Device: %s\n", dev);

	//  Step 1: Open live pcap session on NIC
	pcap_t *handle; /* Session handle */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s.\n", dev);
		return (2);
	}

	// Step 2: Compile filter_exp into BPF psuedo-code
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't compile filter: %s.\n", filter_exp);
		return (2);
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't set filter: %s.\n", filter_exp);
		return (2);
	}

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); // Close the handle
	return 0;
}