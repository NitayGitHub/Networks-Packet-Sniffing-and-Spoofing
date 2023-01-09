#include <stdio.h>
#include <pcap.h>
#include <stdint.h>

typedef unsigned char u_char;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  printf("Got a packet\n");
}

// Packet Sniffing using the pcap API
int main(int argc, char *argv[])
{
	char *dev = argv[1]; /* Device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip proto icmp"; /* The filter expression */
	bpf_u_int32 net;					 /* The IP of our sniffing device */

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