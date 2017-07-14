#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include "header.h"
	
unsigned char ip(ip_h *packet, unsigned short *length)
{
	*length = (packet->total_length[0])*0x100 + packet->total_length[1];
	printf("[IP]\n");
	printf("SRC: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", packet->src[i]);
	printf("\t DST: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", packet->dst[i]);
	printf("\n");
	return packet->ver_IHL;
}

unsigned char tcp(tcp_h *packet)
{
	printf("[TCP]\n");
	printf("SRC PORT: %d\tDST PORT: %d\n", packet->src_port[0]*0x100+packet->src_port[1], packet->dst_port[0]*0x100+packet->dst_port[1]);
	return (packet->offset_res>>4);
}

void data(unsigned char *packet, unsigned short length)
{
	printf("%d\n", length);
	int i;
	for (i = 0; i < length; i++)
	{
		printf("%02x ", packet[i]);
	}
	printf("\n");
}

int main()
{
		char *dev;
		char errbuf[PCAP_ERRBUF_SIZE];          //What is PCAP_ERRBUF_SIZE
		pcap_t *handle;
		struct bpf_program fp;
		char filter_exp[] = "tcp port 80";
		bpf_u_int32 mask;
		bpf_u_int32 net;	

		struct pcap_pkthdr *header;
		ether_h *ethernet;
		const u_char *packet;

		unsigned char type[5] = "N";
		unsigned char ver_IHL;
		unsigned char IHL;
		unsigned short total_length;
		unsigned char tcp_offset;


		dev = pcap_lookupdev(errbuf);

		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
		{
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
			net = 0;
			mask = 0;
		}

		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

		
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

		while (1)
		{
			pcap_next_ex(handle, &header, &packet);
			ethernet = (ether_h*)(packet);
			if (ethernet->type == 8)
			{
				strcpy(type, "IP");
			}
			else if (ethernet->type == 1544)
				strcpy(type, "ARP");
			else
				strcpy(type, "NO");
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
			printf("\t[%s]\n", type);
			if(ethernet->type == 0x8)
			{
				ver_IHL = ip((ip_h*)(packet+14), &total_length);
				IHL = ver_IHL & 0xf;
				tcp_offset = tcp((tcp_h*)(packet+14+IHL*4));
				printf("total length: %d\n", total_length);
				printf("ip length: %d\n", IHL*4);
				printf("tcp length: %d\n", tcp_offset*4);
				printf("%d\n", total_length-IHL*4-tcp_offset*4);
				data((unsigned char*)(packet+14+IHL*4+tcp_offset*4), total_length-IHL*4-tcp_offset*4);
			}
			packet = NULL;
		}
		pcap_close(handle);
		return 0;
}
