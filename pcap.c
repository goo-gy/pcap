#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "header.h"
	
unsigned char ip(ip_h *packet, unsigned short *length, unsigned char *protocol)
{
	*length = htons(packet->total_length);
	printf("[IP]\n");
	printf("SRC: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", packet->src[i]);
	printf("\t\tDST: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", packet->dst[i]);
	printf("\n");
	*protocol = packet->protocol;
	return packet->ver_IHL;
}

unsigned char tcp(tcp_h *packet)
{
	printf("SRC PORT: %d\t\t\tDST PORT: %d\n", htons(packet->src_port), htons(packet->dst_port));
	return (packet->offset_res>>4);
}

void data(unsigned char *packet, unsigned short length)
{
	printf("Data length: %d\n", length);
	int i;
	for (i = 0; i < length && i < 1460; i++)
	{
		printf("%c ", packet[i]);
	}
	printf("\n\n");
}

int main()
{
		char *dev;
		char errbuf[PCAP_ERRBUF_SIZE];    
		int is_ok;
		pcap_t *handle;
		struct pcap_pkthdr *header;
		ether_h *ethernet;
		const u_char *packet;

		unsigned char ver_IHL;
		unsigned char IHL;
		unsigned short total_length;
		unsigned char protocol;
		unsigned char tcp_offset;

		dev = pcap_lookupdev(errbuf);

		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		
		while (1)
		{
			is_ok = pcap_next_ex(handle, &header, &packet);
			if(is_ok == 0)
				continue;

			ethernet = (ether_h*)(packet);		// raw data -> ethernet header data
			printf("[Ethernet]\n");
			printf("SRC MAC");
			for (int i = 0; i < 6; i++)
			{
				printf(":%02x", ethernet->src[i]);
			}
			printf("\tDST MAC");
			for (int i = 0; i < 6; i++)
			{
				printf(":%02x", ethernet->dst[i]);
			}
			printf("\n");
			if(htons(ethernet->type) == 0x0800)
			{
				ver_IHL = ip((ip_h*)(packet+14), &total_length, &protocol);
				IHL = ver_IHL & 0xf;
				printf("Total packet length: %d\n", total_length);
				printf("Ip header length: %d\n", IHL*4);
				if(protocol == 0x6)
				{
					printf("[TCP]\n");
					tcp_offset = tcp((tcp_h*)(packet+14+IHL*4));
					printf("Tcp header length: %d\n", tcp_offset*4);
					data((unsigned char*)(packet+14+IHL*4+tcp_offset*4), total_length-IHL*4-tcp_offset*4);
				}
				else if(protocol == 0x11)
					printf("[UDP]\n");
			}
			else if(htons(ethernet->type) == 0x0806)
				printf("[ARP]\n");
			else
				printf("[Else]\n");
			packet = NULL;			//need?
		}
		pcap_close(handle);
		return 0;
}
