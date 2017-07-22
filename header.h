typedef struct ethernet_header
{
		unsigned char dst[6];
		unsigned char src[6];
		unsigned short type;
}ether_h;

typedef struct ip_header
{
	unsigned char ver_IHL;
	unsigned char TOS;
	unsigned short total_length;
	unsigned int something;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char src[4];
	unsigned char dst[4];
}ip_h;

typedef struct tcp_header
{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_number;
	unsigned int ack_number;
	unsigned char offset_res;
}tcp_h;
