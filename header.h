typedef struct ethernet_header
{
		uint8_t dst[6];
		uint8_t src[6];
		uint16_t type;
}ether_h;

typedef struct arp_header
{
	uint16_t hard_type;
	uint16_t proto_type;
	uint8_t hard_length;
	uint8_t proto_length;
	uint16_t opcode;
	uint8_t src_hard[6];
	uint8_t src_proto[4];
	uint8_t dst_hard[6];
	uint8_t dst_proto[4];
}arp_h;

typedef struct ip_header
{
	uint8_t ver_IHL;
	uint8_t TOS;
	uint16_t total_length;
	uint32_t something;
	uint8_t TTL;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src[4];
	uint8_t dst[4];
}ip_h;

typedef struct tcp_header
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_number;
	uint32_t ack_number;
	uint8_t offset_res;
}tcp_h;