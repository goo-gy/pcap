typedef struct ethernet_header
{
		unsigned char dst[6];
		unsigned char src[6];
		unsigned short type;
}ether_h;

typedef struct arp_header
{
	unsigned short hard_type;
	unsigned short proto_type;
	unsigned char hard_length;
	unsigned char proto_length;
	unsigned short opcode;
	unsigned char src_hard[6];
	unsigned char src_proto[4];
	unsigned char dst_hard[6];
	unsigned char dst_proto[4];
}arp_h;

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
