#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "header.h"
	
unsigned char ip(ip_h *packet, unsigned short *total_length, unsigned char *ip_header_length)
{
	*total_length = htons(packet->total_length);
	*ip_header_length = (packet->ver_IHL & 0xf)*4;

	printf("[IP]\n");
	printf("SRC: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", packet->src[i]);
	printf("\t\tDST: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", packet->dst[i]);
	printf("\n");

	return packet->protocol;
}

unsigned char tcp(tcp_h *packet, unsigned char *tcp_header_length)
{
	unsigned char is_http = 0;
	unsigned short src_port, dst_port;
	printf("SRC PORT: %d\t\t\tDST PORT: %d\n", src_port = htons(packet->src_port), dst_port = htons(packet->dst_port));

	if(src_port == 80 || dst_port == 80)
		is_http = 1;

	*tcp_header_length = (packet->offset_res>>4)*4;
	return is_http;
}

void data(unsigned char *packet, unsigned short length)
{
	printf("Data length: %d\n", length);
	printf("---------------------------------------------------------------\n");
	int i;
	for (i = 0; i < length && i < 1460; i++)
	{
		printf("%c", packet[i]);
	}
	printf("---------------------------------------------------------------\n\n");
}

int main(int argc, char *argv[])
{
		char *dev;
		char errbuf[PCAP_ERRBUF_SIZE];    
		int is_ok;
		pcap_t *handle = NULL;
		struct pcap_pkthdr *header;
		ether_h *ethernet;
		const u_char *packet;

		unsigned short total_length;
		unsigned char ip_header_length;
		unsigned char protocol;

		unsigned char tcp_header_length;
		unsigned char is_http = 0;

		if(argc == 1)
		{
			dev = pcap_lookupdev(errbuf);
			handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		}
		else if(argc ==2)
		{
			handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
		}
		else
		{
			printf("Please Just one device.\n");
			return 0;
		}
		if(!handle)
		{
			printf("Device is not loaded.\n");	
			return 0;
		}
	
		while (1)
		{
			is_ok = pcap_next_ex(handle, &header, &packet);
			if(is_ok == 0)
				continue;
			else if(is_ok == -1)
				break;
			else if(is_ok == -2)
			{
				printf("[End of File]\n");
				break;
			}

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
				protocol = ip((ip_h*)(packet+14), &total_length, &ip_header_length);
				printf("Total packet length: %d\n", total_length);
				printf("Ip header length: %d\n", ip_header_length);
				if(protocol == 0x6)
				{
					printf("[TCP]\n");
					is_http = tcp((tcp_h*)(packet+14+ip_header_length), &tcp_header_length);
					printf("Tcp header length: %d\n", tcp_header_length);
					if(is_http == 1)
					{
						printf("[HTTP]\n");
						data((unsigned char*)(packet+14+ip_header_length+tcp_header_length), total_length-ip_header_length-tcp_header_length);
					}
					else
					{
						printf("[Not HTTP]\n\n");
					}
				}
				else if(protocol == 0x11)
					printf("[UDP]\n\n");
			}
			else if(htons(ethernet->type) == 0x0806)
				printf("[ARP]\n\n");
			else
				printf("[Else]\n\n");
			packet = NULL;			//need?
		}
		pcap_close(handle);
		return 0;
}
