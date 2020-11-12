#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include "header.h"

u_char* prase_ip(u_char *packet, uint8_t *protocol, uint16_t *total_length)
{
    ip_h *ip_packet = (ip_h*)packet;
    uint8_t ip_header_length = (ip_packet->ver_IHL & 0xf)*4;

	printf("[IP] ");
	printf("SRC: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", ip_packet->src[i]);
	printf("\t\tDST: ");
	for (int i = 0; i < 4; i++)
		printf("%d.", ip_packet->dst[i]);
	printf("\n");

    *protocol = ip_packet->protocol;
    *total_length = ntohs(ip_packet->total_length);

    return packet+ip_header_length;
}

u_char *parse_tcp(u_char *packet_start, u_char* packet, uint16_t total_length)
{
    tcp_h *tcp_packet = (tcp_h*)packet;
    uint16_t src_port, dst_port;
    src_port = ntohs(tcp_packet->src_port);
    dst_port = ntohs(tcp_packet->dst_port);
    printf("[TCP] SRC PORT: %d\t\t\tDST PORT: %d\n", src_port, dst_port);

    u_int tcp_length = (tcp_packet->offset_res>>4)*4;
    u_char *data = packet+tcp_length;
    if(dst_port == 80)
    {
        show_data(data, total_length - (packet - packet_start));
    }
}

int show_data(u_char* data, u_int size)
{
    for(uint i = 0; i < size; i++)
    {
        printf("%c", data[i]);
    }
}

int process_data(pcap_t *handle)
{
    u_char* packet;
    struct pcap_pkthdr *header;
    ether_h *ethernet;

    uint8_t protocol;
    uint16_t total_length;

    u_char *packet_pointer;
    while(1)
    {
        pcap_next_ex(handle, &header, &packet);
        ethernet = (ether_h*)packet;

        if(ntohs(ethernet->type) == 0x0800)
        {
            packet_pointer = prase_ip(packet+14, &protocol, &total_length);
            if(protocol == 0x06) // TCP
            {
                parse_tcp(packet, packet_pointer, total_length);
            }
        }
        packet = NULL;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = NULL;
    if(argc == 1)
    {
        dev = pcap_lookupdev(errbuf);
        printf("Loading device: [%s]\n", dev);
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    }
    else if(argc == 2)
    {
        handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    }
    else
    {
        printf("<Usage>\n");
        printf("sudo ./pcap\n");
        printf("sudo ./pcap [device name]\n");
        return -1;
    }
    if(handle == NULL)
    {
        printf("%s\n", errbuf);
        return -1;
    }

    process_data(handle);
}