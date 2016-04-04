#include <linux/types.h>

//#define DEBUG_AGGREGATE
#define XT_TRAFSTAT_PORTS 32

#ifdef __KERNEL__
/* networking options for handling packet's data */
typedef struct net_options {
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	char  *pkt_data;
	__u8   syn_flag;
	__u16  local_port;
	__u16  remote_port;
	__u32  pkt_len;
} net_options;

/* networking statistics per IP address */
typedef struct traf_stat {
        struct {
	        __u32  local_addr;
	        __u32  remote_addr;
	        __u16  local_port;
	        __u16  remote_port;
 	        __u8   protocol;
        } traf;
        struct {
	        __u32  local_pkt;
	        __u32  remote_pkt;
	        __u64  local_data;
	        __u64  remote_data;
	        __u32  syn_count;
        } stat;
	struct rb_node node;
} traf_stat;

/* ports storage */
typedef struct traf_ports {
        struct data {
	        __u16  port;
	        __u8   direction;
	        __u8   protocol;
        } data;
	struct rb_node node;
} traf_ports;
#endif

struct traf_thread;

/* xtables options */
struct ports { 
        __u16 tcp_ports; 
        __u16 udp_ports; 
};

struct port_search_helper {
        struct ports local;
        struct ports remote;
};

struct xt_TRAFSTAT_info {
	union nf_inet_addr addr, mask;
	__u8  bitmask;
	__u32 local_net;
	__u16 local_tcp_ports[XT_TRAFSTAT_PORTS];
	__u16 local_udp_ports[XT_TRAFSTAT_PORTS];
	__u16 remote_tcp_ports[XT_TRAFSTAT_PORTS];
	__u16 remote_udp_ports[XT_TRAFSTAT_PORTS];
        __u32 max_entries;
	__u32 traf_policy;
        __u32 min_pkt_spoof;
        __u32 sample_tcp_s;
        __u32 sample_tcp_a; 
        __u32 sample_udp_a;
        __u8  fast_aggregate;
        __u8  dump_prio;
        struct port_search_helper psh;
        struct traf_thread *tt __attribute__((aligned(8)));
};
