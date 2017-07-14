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
	unsigned char total_length[2];
	unsigned char something[4];
	unsigned char TTL;
	unsigned char protocol;
	unsigned char checksum[2];
	unsigned char src[4];
	unsigned char dst[4];
}ip_h;

typedef struct tcp_header
{
	unsigned char src_port[2];
	unsigned char dst_port[2];
	unsigned int don_use[2];
	unsigned char offset_res;
}tcp_h;
