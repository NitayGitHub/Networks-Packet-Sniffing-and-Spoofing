#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>	 //Provides declarations for udp header
#include <netinet/tcp.h>	 //Provides declarations for tcp header
#include <netinet/ip.h>		 //Provides declarations for ip header

void process_ip_packet(const u_char *, int);
void print_ip_packet(const u_char *, int);
void print_tcp_packet(const u_char *, int);
void PrintData(const u_char *, int);

FILE *logfile;
struct sockaddr_in source, dest;
int tcp = 0, others = 0, total = 0, i, j;

typedef unsigned char u_char;
typedef unsigned short u_short;

void PrintData (const u_char * data , int Size)
{
	int i , j;
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile , "         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile , "."); //otherwise print a dot
			}
			fprintf(logfile , "\n");
		} 
		
		if(i%16==0) fprintf(logfile , "   ");
			fprintf(logfile , " %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  fprintf(logfile , "   "); //extra spaces
			}
			
			fprintf(logfile , "         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  fprintf(logfile , "%c",(unsigned char)data[j]);
				}
				else 
				{
				  fprintf(logfile , ".");
				}
			}
			
			fprintf(logfile ,  "\n" );
		}
	}
}

void print_ip_header(const u_char *Buffer, int Size)
{

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	//fprintf(logfile, "\n");
	//fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   |Packet No.   : %d\n", total);
	//fprintf(logfile, "   |-IP Version        : %d\n", (unsigned int)iph->version);
	//fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	//fprintf(logfile, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	//fprintf(logfile, "   |-Identification    : %d\n", ntohs(iph->id));
	// fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	// fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	// fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	//fprintf(logfile, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
	//fprintf(logfile, "   |-Protocol : %d\n", (unsigned int)iph->protocol);
	//fprintf(logfile, "   |-Checksum : %d\n", ntohs(iph->check));
	fprintf(logfile, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	fprintf(logfile, "   |-Timestamp      : %ld\n", header->ts.tv_sec);

	// Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) // Check the Protocol and do accordingly...
	{
	case 6: // TCP Protocol
		++tcp;
		print_tcp_packet(buffer, size);
		break;

	default: // Some Other Protocol like ARP etc.
		++others;
		break;
	}
}

void print_tcp_packet(const u_char *Buffer, int Size)
{
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr *tcph = (struct tcphdr *)(Buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	//fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

	print_ip_header(Buffer, Size);

	//fprintf(logfile, "\n");
	//fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "   |-Source Port      : %u\n", ntohs(tcph->source));
	fprintf(logfile, "   |-Destination Port : %u\n", ntohs(tcph->dest));
	//fprintf(logfile, "   |-Sequence Number    : %u\n", ntohl(tcph->seq));
	//fprintf(logfile, "   |-Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
	//fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
	// fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	// fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	//fprintf(logfile, "   |-Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	//fprintf(logfile, "   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	//fprintf(logfile, "   |-Push Flag            : %d\n", (unsigned int)tcph->psh);
	//fprintf(logfile, "   |-Reset Flag           : %d\n", (unsigned int)tcph->rst);
	//fprintf(logfile, "   |-Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	//fprintf(logfile, "   |-Finish Flag          : %d\n", (unsigned int)tcph->fin);
	
	//fprintf(logfile, "   |-Window         : %d\n", ntohs(tcph->window));
	//fprintf(logfile, "   |-Checksum       : %d\n", ntohs(tcph->check));
	//fprintf(logfile, "   |-Urgent Pointer : %d\n", tcph->urg_ptr);
	fprintf(logfile, "\n");
	fprintf(logfile , "                        DATA                         ");
	fprintf(logfile , "\n");
		
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfile , "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
	fprintf(logfile, "\n###########################################################\n");
}

// Packet Sniffing using the pcap API
int main()
{
	struct bpf_program fp;
	char filter_exp[] = "tcp portrange 9998-9999"; /* The filter expression */
	bpf_u_int32 net;							   /* The IP of our sniffing device */
	pcap_if_t *alldevsp, *device;
	pcap_t *handle; // Handle of the device that shall be sniffed
	char errbuf[100], *devname, devs[100][100];
	int count = 1, n;

	// First get the list of available devices
	printf("Finding available devices ... ");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("Error finding devices : %s", errbuf);
		exit(1);
	}
	printf("Done");

	// Print the available devices
	printf("\nAvailable Devices are :\n");
	for (device = alldevsp; device != NULL; device = device->next)
	{
		printf("%d. %s - %s\n", count, device->name, device->description);
		if (device->name != NULL)
		{
			strcpy(devs[count], device->name);
		}
		count++;
	}

	// Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d", &n);
	devname = devs[n];

	printf("Device: %s\n", devname);

	//  Step 1: Open live pcap session on NIC
	handle = pcap_open_live(devname, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s.\n", devname);
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

	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
	{
		printf("Unable to create file.");
	}

	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); // Close the handle
	return 0;
}